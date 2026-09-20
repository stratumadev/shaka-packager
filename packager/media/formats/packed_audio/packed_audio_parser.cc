// Copyright 2026 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <packager/media/formats/packed_audio/packed_audio_parser.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <absl/log/log.h>

#include <packager/media/base/aes_decryptor.h>
#include <packager/media/base/audio_stream_info.h>
#include <packager/media/base/audio_timestamp_helper.h>
#include <packager/media/base/buffer_reader.h>
#include <packager/media/base/fourccs.h>
#include <packager/media/base/key_source.h>
#include <packager/media/base/media_sample.h>
#include <packager/media/base/timestamp.h>
#include <packager/media/formats/mp2t/ac3_header.h>
#include <packager/media/formats/packed_audio/packed_audio_constants.h>

namespace shaka {
namespace media {
namespace {

constexpr size_t kId3HeaderSize = 10;
constexpr size_t kId3FrameHeaderSize = 10;
constexpr size_t kMaxId3TagSize = 1024 * 1024;
constexpr size_t kAc3LeadingClearBytes = 16;
constexpr uint32_t kPackedAudioTrackId = 1;
constexpr int64_t kTimestampRollover = 1LL << 33;
constexpr int64_t kTimestampMask = kTimestampRollover - 1;

bool IsSynchsafe(const uint8_t* value, size_t size) {
  return std::all_of(value, value + size,
                     [](uint8_t byte) { return (byte & 0x80) == 0; });
}

uint32_t ReadSynchsafe(const uint8_t* value) {
  return (static_cast<uint32_t>(value[0]) << 21) |
         (static_cast<uint32_t>(value[1]) << 14) |
         (static_cast<uint32_t>(value[2]) << 7) | value[3];
}

bool StartsWithId3(const std::vector<uint8_t>& buffer, size_t position) {
  return buffer.size() - position >= 3 && buffer[position] == 'I' &&
         buffer[position + 1] == 'D' && buffer[position + 2] == '3';
}

}  // namespace

PackedAudioParser::PackedAudioParser() = default;
PackedAudioParser::~PackedAudioParser() = default;

void PackedAudioParser::Init(const InitCB& init_cb,
                             const NewMediaSampleCB& new_media_sample_cb,
                             const NewTextSampleCB& new_text_sample_cb,
                             KeySource* decryption_key_source) {
  init_cb_ = init_cb;
  new_media_sample_cb_ = new_media_sample_cb;
  decryption_key_source_ = decryption_key_source;
  buffer_.clear();
  buffer_position_ = 0;
  decryptor_.reset();
  timestamp_helper_.reset();
  audio_config_.clear();
  initialized_ = false;
  have_segment_ = false;
  segment_is_encrypted_ = false;
  next_timestamp_ = 0;
  last_emitted_timestamp_ = kNoTimestamp;
}

bool PackedAudioParser::Parse(const uint8_t* buf, int size) {
  if (!buf || size < 0) {
    LOG(ERROR) << "Invalid packed audio input.";
    return false;
  }
  if (buffer_position_ > 0) {
    buffer_.erase(buffer_.begin(), buffer_.begin() + buffer_position_);
    buffer_position_ = 0;
  }
  if (size > 0)
    buffer_.insert(buffer_.end(), buf, buf + size);
  return ParseAvailable();
}

bool PackedAudioParser::Flush() {
  if (!ParseAvailable())
    return false;
  if (buffer_position_ != buffer_.size()) {
    LOG(ERROR) << "Truncated packed AC-3 segment.";
    return false;
  }
  const bool result = have_segment_ && initialized_;
  buffer_.clear();
  buffer_position_ = 0;
  decryptor_.reset();
  have_segment_ = false;
  segment_is_encrypted_ = false;
  next_timestamp_ = 0;
  last_emitted_timestamp_ = kNoTimestamp;
  return result;
}

bool PackedAudioParser::ParseAvailable() {
  while (buffer_position_ < buffer_.size()) {
    if (buffer_.size() - buffer_position_ < 3)
      break;
    const size_t position_before_parse = buffer_position_;
    if (StartsWithId3(buffer_, buffer_position_)) {
      if (!ParseId3Tag())
        return false;
    } else {
      if (!ParseAc3Frame())
        return false;
    }
    if (buffer_position_ == position_before_parse)
      break;
  }
  return true;
}

bool PackedAudioParser::ParseId3Tag() {
  const size_t available = buffer_.size() - buffer_position_;
  if (available < kId3HeaderSize)
    return true;

  const uint8_t* tag = buffer_.data() + buffer_position_;
  if (tag[3] != 4 || tag[4] != 0 || tag[5] != 0 || !IsSynchsafe(tag + 6, 4)) {
    LOG(ERROR) << "Unsupported ID3 tag in packed AC-3 input.";
    return false;
  }
  const size_t payload_size = ReadSynchsafe(tag + 6);
  if (payload_size > kMaxId3TagSize) {
    LOG(ERROR) << "Packed AC-3 ID3 tag exceeds size limit.";
    return false;
  }
  const size_t tag_size = kId3HeaderSize + payload_size;
  if (available < tag_size)
    return true;

  bool found_timestamp = false;
  bool encrypted = false;
  int64_t timestamp = 0;
  size_t position = kId3HeaderSize;
  while (position < tag_size) {
    const size_t remaining = tag_size - position;
    if (std::all_of(tag + position, tag + tag_size,
                    [](uint8_t byte) { return byte == 0; })) {
      position = tag_size;
      break;
    }
    if (remaining < kId3FrameHeaderSize) {
      LOG(ERROR) << "Truncated ID3 frame in packed AC-3 input.";
      return false;
    }
    const uint8_t* frame = tag + position;
    if (!IsSynchsafe(frame + 4, 4) || frame[8] != 0 || frame[9] != 0) {
      LOG(ERROR) << "Unsupported ID3 frame in packed AC-3 input.";
      return false;
    }
    const size_t frame_size = ReadSynchsafe(frame + 4);
    if (frame_size > tag_size - position - kId3FrameHeaderSize) {
      LOG(ERROR) << "Invalid ID3 frame length in packed AC-3 input.";
      return false;
    }
    const uint8_t* frame_data = frame + kId3FrameHeaderSize;
    if (std::memcmp(frame, "PRIV", 4) == 0) {
      const uint8_t* nul = static_cast<const uint8_t*>(
          std::memchr(frame_data, '\0', frame_size));
      if (!nul) {
        LOG(ERROR) << "ID3 PRIV frame has no owner identifier.";
        return false;
      }
      const std::string owner(reinterpret_cast<const char*>(frame_data),
                              nul - frame_data);
      const uint8_t* data = nul + 1;
      const size_t data_size = frame_size - (data - frame_data);
      BufferReader reader(data, data_size);
      if (owner == kTimestampOwnerIdentifier) {
        if (found_timestamp || data_size != sizeof(uint64_t)) {
          LOG(ERROR) << "Invalid packed AC-3 transport timestamp.";
          return false;
        }
        uint64_t raw_timestamp;
        if (!reader.Read8(&raw_timestamp) ||
            raw_timestamp > static_cast<uint64_t>(kTimestampMask)) {
          LOG(ERROR) << "Invalid packed AC-3 transport timestamp range.";
          return false;
        }
        timestamp = static_cast<int64_t>(raw_timestamp);
        if (have_segment_) {
          const int64_t current_cycle = next_timestamp_ / kTimestampRollover;
          timestamp += current_cycle * kTimestampRollover;
          if (timestamp < next_timestamp_ - kTimestampRollover / 2)
            timestamp += kTimestampRollover;
        }
        found_timestamp = true;
      } else if (owner == kAudioDescriptionOwnerIdentifier) {
        uint32_t format;
        uint8_t version;
        uint8_t setup_size;
        if (encrypted || !reader.Read4(&format) || format != FOURCC_zac3 ||
            !reader.SkipBytes(2) || !reader.Read1(&version) || version != 1 ||
            !reader.Read1(&setup_size) ||
            reader.size() - reader.pos() != setup_size) {
          LOG(ERROR) << "Only encrypted AC-3 packed audio is supported.";
          return false;
        }
        encrypted = true;
      }
    }
    position += kId3FrameHeaderSize + frame_size;
  }
  if (!found_timestamp) {
    LOG(ERROR) << "Packed AC-3 segment is missing its ID3 timestamp.";
    return false;
  }
  if (last_emitted_timestamp_ != kNoTimestamp &&
      timestamp <= last_emitted_timestamp_) {
    LOG(ERROR) << "Packed AC-3 segment timestamp moves backwards.";
    return false;
  }

  if (encrypted) {
    if (!decryption_key_source_) {
      LOG(ERROR) << "Encrypted packed AC-3 requires a key source.";
      return false;
    }
    EncryptionKey key;
    const Status status = decryption_key_source_->GetKey(std::string(), &key);
    if (!status.ok()) {
      LOG(ERROR) << "Unable to retrieve packed AC-3 decryption key: "
                 << status.ToString();
      return false;
    }
    if (key.iv.size() != 16) {
      LOG(ERROR) << "Encrypted packed AC-3 requires an explicit 16-byte IV.";
      return false;
    }
    decryptor_ = std::make_unique<AesCbcDecryptor>(kNoPadding,
                                                   AesCryptor::kUseConstantIv);
    if (!decryptor_->InitializeWithIv(key.key, key.iv)) {
      LOG(ERROR) << "Unable to initialize packed AC-3 decryptor.";
      return false;
    }
  } else {
    decryptor_.reset();
  }

  buffer_position_ += tag_size;
  next_timestamp_ = timestamp;
  if (timestamp_helper_)
    timestamp_helper_->SetBaseTimestamp(timestamp);
  segment_is_encrypted_ = encrypted;
  have_segment_ = true;
  return true;
}

bool PackedAudioParser::ParseAc3Frame() {
  if (!have_segment_) {
    LOG(ERROR) << "Packed AC-3 audio is missing its leading ID3 tag.";
    return false;
  }

  mp2t::Ac3Header header;
  const size_t available = buffer_.size() - buffer_position_;
  if (available < header.GetMinFrameSize())
    return true;
  const uint8_t* frame_data = buffer_.data() + buffer_position_;
  if (!header.IsSyncWord(frame_data) || ((frame_data[5] >> 3) & 0x1F) >= 10 ||
      !header.Parse(frame_data, available)) {
    LOG(ERROR) << "Invalid AC-3 frame in packed audio input.";
    return false;
  }
  const size_t frame_size = header.GetFrameSize();
  if (available < frame_size)
    return true;

  if (!initialized_) {
    if (!EmitStreamInfo(header))
      return false;
  } else {
    std::vector<uint8_t> config;
    header.GetAudioSpecificConfig(&config);
    if (config != audio_config_) {
      LOG(ERROR) << "Packed AC-3 stream configuration changed mid-stream.";
      return false;
    }
  }

  std::vector<uint8_t> frame(frame_data, frame_data + frame_size);
  if (segment_is_encrypted_ && !DecryptAc3Frame(&frame))
    return false;

  const int64_t duration =
      timestamp_helper_->GetFrameDuration(header.GetSamplesPerFrame());
  if (duration <= 0) {
    LOG(ERROR) << "Invalid AC-3 sample duration.";
    return false;
  }
  std::shared_ptr<MediaSample> sample =
      MediaSample::CopyFrom(frame.data(), frame.size(), true);
  const int64_t sample_timestamp = timestamp_helper_->GetTimestamp();
  sample->set_dts(sample_timestamp);
  sample->set_pts(sample_timestamp);
  sample->set_duration(duration);
  if (!new_media_sample_cb_ ||
      !new_media_sample_cb_(kPackedAudioTrackId, std::move(sample))) {
    LOG(ERROR) << "Packed AC-3 sample callback rejected a frame.";
    return false;
  }
  timestamp_helper_->AddFrames(header.GetSamplesPerFrame());
  next_timestamp_ = timestamp_helper_->GetTimestamp();
  last_emitted_timestamp_ = sample_timestamp;
  buffer_position_ += frame_size;
  return true;
}

bool PackedAudioParser::EmitStreamInfo(const mp2t::Ac3Header& header) {
  std::vector<uint8_t> config;
  header.GetAudioSpecificConfig(&config);
  std::shared_ptr<StreamInfo> stream(new AudioStreamInfo(
      kPackedAudioTrackId, kPackedAudioTimescale, kInfiniteDuration, kCodecAC3,
      AudioStreamInfo::GetCodecString(kCodecAC3, 0), config.data(),
      config.size(), 16, header.GetNumChannels(), header.GetSamplingFrequency(),
      0, 0, 0, 0, "und", false));
  if (!stream->IsValidConfig()) {
    LOG(ERROR) << "Invalid AC-3 stream configuration.";
    return false;
  }
  if (init_cb_)
    init_cb_({stream});
  timestamp_helper_ = std::make_unique<AudioTimestampHelper>(
      kPackedAudioTimescale, header.GetSamplingFrequency());
  timestamp_helper_->SetBaseTimestamp(next_timestamp_);
  audio_config_ = config;
  initialized_ = true;
  return true;
}

bool PackedAudioParser::DecryptAc3Frame(std::vector<uint8_t>* frame) {
  if (!decryptor_ || frame->size() < kAc3LeadingClearBytes) {
    LOG(ERROR) << "Invalid encrypted AC-3 frame.";
    return false;
  }
  const size_t encrypted_size =
      ((frame->size() - kAc3LeadingClearBytes) / 16) * 16;
  if (encrypted_size == 0)
    return true;
  return decryptor_->Crypt(frame->data() + kAc3LeadingClearBytes,
                           encrypted_size,
                           frame->data() + kAc3LeadingClearBytes);
}

}  // namespace media
}  // namespace shaka
