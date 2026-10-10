// Copyright 2026 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <packager/media/formats/packed_audio/packed_audio_parser.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <absl/log/log.h>

#include <packager/media/base/aes_decryptor.h>
#include <packager/media/base/audio_stream_info.h>
#include <packager/media/base/audio_timestamp_helper.h>
#include <packager/media/base/bit_reader.h>
#include <packager/media/base/buffer_reader.h>
#include <packager/media/base/fourccs.h>
#include <packager/media/base/key_source.h>
#include <packager/media/base/media_sample.h>
#include <packager/media/base/timestamp.h>
#include <packager/media/codecs/aac_audio_specific_config.h>
#include <packager/media/codecs/ec3_audio_util.h>
#include <packager/media/formats/mp2t/ac3_header.h>
#include <packager/media/formats/mp2t/adts_header.h>
#include <packager/media/formats/packed_audio/packed_audio_constants.h>

namespace shaka {
namespace media {
namespace {

constexpr size_t kId3HeaderSize = 10;
constexpr size_t kId3FrameHeaderSize = 10;
constexpr size_t kMaxId3TagSize = 1024 * 1024;
constexpr size_t kMaxAudioSetupSearchBytes = 16 * 1024 * 1024;
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

uint16_t Ac3Crc(const uint8_t* data, size_t size) {
  static const std::array<uint16_t, 256> table = [] {
    std::array<uint16_t, 256> values{};
    for (size_t i = 0; i < values.size(); ++i) {
      uint16_t crc = i << 8;
      for (int bit = 0; bit < 8; ++bit)
        crc = (crc << 1) ^ ((crc & 0x8000) ? 0x8005 : 0);
      values[i] = crc;
    }
    return values;
  }();
  uint16_t crc = 0;
  for (size_t i = 0; i < size; ++i)
    crc = (crc << 8) ^ table[(crc >> 8) ^ data[i]];
  return crc;
}

bool HasValidAc3Crc(const std::vector<uint8_t>& frame) {
  // AC-3 divides the frame in 16-bit words, including at 44.1 kHz.
  const size_t split = ((frame.size() >> 2) + (frame.size() >> 4)) << 1;
  return split > 2 && split < frame.size() &&
         Ac3Crc(frame.data() + 2, split - 2) == 0 &&
         Ac3Crc(frame.data() + split, frame.size() - split) == 0;
}

// A zero CBC IV only corrupts bytes 16..31 of SAMPLE-AES AC-3. Recover them
// from uniform coupling coordinates observed on both sides, then require both
// CRCs. This first-frame heuristic is best effort, not cryptographic
// authentication; an explicit IV always takes precedence.
bool RecoverAc3Iv(std::vector<uint8_t>* frame, std::vector<uint8_t>* iv) {
  if (frame->size() < 32)
    return false;
  BitReader bits(frame->data(), kAc3LeadingClearBytes);
  uint8_t channel_mode;
  if (!bits.SkipBits(48) || !bits.ReadBits(3, &channel_mode) ||
      channel_mode < 2)
    return false;
  if ((channel_mode & 1) && !bits.SkipBits(2))
    return false;
  if ((channel_mode & 4) && !bits.SkipBits(2))
    return false;
  if (channel_mode == 2 && !bits.SkipBits(2))
    return false;
  // LFE, dialnorm, compression, language, audio production information,
  // copyright/original flags, then timecodes (or alternate BSI fields).
  if (!bits.SkipBits(6) || !bits.SkipBitsConditional(true, 8) ||
      !bits.SkipBitsConditional(true, 8) ||
      !bits.SkipBitsConditional(true, 7) || !bits.SkipBits(2) ||
      !bits.SkipBitsConditional(true, 14) ||
      !bits.SkipBitsConditional(true, 14))
    return false;
  bool additional_bsi;
  if (!bits.ReadBits(1, &additional_bsi))
    return false;
  if (additional_bsi) {
    uint8_t length;
    if (!bits.ReadBits(6, &length) || !bits.SkipBits((length + 1) * 8))
      return false;
  }
  constexpr uint8_t kFullBandwidthChannels[] = {2, 1, 2, 3, 3, 4, 4, 5};
  const uint8_t channels = kFullBandwidthChannels[channel_mode];
  bool coupling_strategy;
  bool coupling_in_use;
  if (!bits.SkipBits(channels * 2) ||  // Block switching and dither flags.
      !bits.SkipBitsConditional(true, 8) ||
      !bits.ReadBits(1, &coupling_strategy) || !coupling_strategy ||
      !bits.ReadBits(1, &coupling_in_use) || !coupling_in_use)
    return false;
  size_t coupled_channels = 0;
  for (size_t channel = 0; channel < channels; ++channel) {
    bool coupled;
    if (!bits.ReadBits(1, &coupled))
      return false;
    coupled_channels += coupled;
  }
  if (coupled_channels < 2 || (channel_mode == 2 && !bits.SkipBits(1)))
    return false;
  uint8_t begin;
  uint8_t end;
  if (!bits.ReadBits(4, &begin) || !bits.ReadBits(4, &end) || begin >= end + 3)
    return false;
  size_t bands = 1;
  for (int subband = begin + 1; subband < end + 3; ++subband) {
    bool combined;
    if (!bits.ReadBits(1, &combined))
      return false;
    bands += !combined;
  }
  const size_t start = bits.bit_position();
  bool coordinates_exist;
  uint8_t master;
  uint8_t coordinate;
  if (!bits.ReadBits(1, &coordinates_exist) || !coordinates_exist ||
      !bits.ReadBits(2, &master) || !bits.ReadBits(8, &coordinate))
    return false;

  const size_t channel_bits = 3 + bands * 8;
  const size_t finish = start + coupled_channels * channel_bits;
  // Require at least a full coordinate on each side of the unknown block.
  if (finish < 264 || finish > frame->size() * 8)
    return false;
  std::vector<uint8_t> corrected(*frame);
  for (size_t position = start; position < finish; ++position) {
    const size_t relative = (position - start) % channel_bits;
    const uint8_t expected = relative == 0 ? 1
                             : relative < 3
                                 ? (master >> (2 - relative)) & 1
                                 : (coordinate >> (7 - (relative - 3) % 8)) & 1;
    const uint8_t mask = 1 << (7 - position % 8);
    if (position < 128 || position >= 256) {
      if (((*frame)[position / 8] & mask) != (expected ? mask : 0))
        return false;
    } else {
      corrected[position / 8] =
          (corrected[position / 8] & ~mask) | (expected ? mask : 0);
    }
  }
  if (!HasValidAc3Crc(corrected))
    return false;
  iv->resize(16);
  for (size_t i = 0; i < iv->size(); ++i)
    (*iv)[i] = (*frame)[16 + i] ^ corrected[16 + i];
  *frame = std::move(corrected);
  return true;
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
  decryption_key_.clear();
  recovered_iv_.clear();
  recover_missing_iv_ = false;
  timestamp_helper_.reset();
  audio_config_.clear();
  aac_adts_config_.clear();
  ec3_frame_.clear();
  audio_setup_position_ = 0;
  audio_type_ = 0;
  ec3_sampling_frequency_ = 0;
  ec3_blocks_ = 0;
  ec3_frame_blocks_ = 0;
  ec3_dependents_ = 0;
  ec3_expected_dependents_ = 0;
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
  if (buffer_position_ != buffer_.size() || !ec3_frame_.empty()) {
    LOG(ERROR) << "Truncated packed audio segment or E-AC-3 access unit.";
    return false;
  }
  // Demuxer may flush twice for inputs smaller than its probe buffer.
  const bool result = initialized_;
  buffer_.clear();
  buffer_position_ = 0;
  decryptor_.reset();
  decryption_key_.clear();
  recovered_iv_.clear();
  recover_missing_iv_ = false;
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
      if (buffer_.size() - buffer_position_ < 6)
        break;
      const bool is_aac = buffer_[buffer_position_] == 0xff &&
                          (buffer_[buffer_position_ + 1] & 0xf6) == 0xf0;
      const uint8_t bsid = (buffer_[buffer_position_ + 5] >> 3) & 0x1f;
      const bool is_ec3 = !is_aac && bsid >= 11 && bsid <= 16;
      if (have_segment_ && audio_type_ == 0 && !segment_is_encrypted_ &&
          (is_ec3 || (is_aac && decryption_key_source_))) {
        const size_t position = buffer_position_;
        const int64_t timestamp = next_timestamp_;
        while (audio_type_ == 0) {
          if (audio_setup_position_ >= kMaxAudioSetupSearchBytes) {
            LOG(ERROR) << "No audio setup within 16 MiB of the clear lead.";
            return false;
          }
          const size_t setup_position = position + audio_setup_position_;
          const size_t available = buffer_.size() - setup_position;
          if (available < 6)
            return true;
          if (StartsWithId3(buffer_, setup_position)) {
            buffer_position_ = setup_position;
            const bool parsed = ParseId3Tag();
            const size_t tag_end = buffer_position_;
            buffer_position_ = position;
            next_timestamp_ = timestamp;
            segment_is_encrypted_ = false;
            if (!parsed)
              return false;
            if (tag_end == setup_position)
              return true;
            audio_setup_position_ = tag_end - position;
          } else if (is_aac) {
            if (available < 7)
              return true;
            mp2t::AdtsHeader header;
            const uint8_t* frame = buffer_.data() + setup_position;
            if (!header.IsSyncWord(frame) || !header.Parse(frame, available) ||
                header.GetFrameSize() <= header.GetHeaderSize()) {
              LOG(ERROR) << "Invalid AAC clear lead.";
              return false;
            }
            if (available < header.GetFrameSize())
              return true;
            audio_setup_position_ += header.GetFrameSize();
          } else {
            const uint8_t* frame = buffer_.data() + setup_position;
            const size_t size = ((((frame[2] & 7) << 8) | frame[3]) + 1) * 2;
            const uint8_t setup_bsid = frame[5] >> 3;
            if (frame[0] != 0x0b || frame[1] != 0x77 ||
                size < kAc3LeadingClearBytes || setup_bsid < 11 ||
                setup_bsid > 16) {
              LOG(ERROR) << "Invalid packed audio clear lead.";
              return false;
            }
            if (available < size)
              return true;
            audio_setup_position_ += size;
          }
        }
        audio_setup_position_ = 0;
      }
      if (is_aac) {
        if (!ParseAacFrame())
          return false;
      } else if (is_ec3) {
        if (!ParseEc3Frame())
          return false;
      } else if (!ParseAc3Frame()) {
        return false;
      }
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
    LOG(ERROR) << "Unsupported ID3 tag in packed audio input.";
    return false;
  }
  const size_t payload_size = ReadSynchsafe(tag + 6);
  if (payload_size > kMaxId3TagSize) {
    LOG(ERROR) << "Packed audio ID3 tag exceeds size limit.";
    return false;
  }
  const size_t tag_size = kId3HeaderSize + payload_size;
  if (available < tag_size)
    return true;

  if (!ec3_frame_.empty()) {
    LOG(ERROR) << "ID3 segment boundary splits an E-AC-3 access unit.";
    return false;
  }

  bool found_timestamp = false;
  bool encrypted = false;
  uint32_t audio_type = 0;
  std::vector<uint8_t> setup_config;
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
      LOG(ERROR) << "Truncated ID3 frame in packed audio input.";
      return false;
    }
    const uint8_t* frame = tag + position;
    if (!IsSynchsafe(frame + 4, 4) || frame[8] != 0 || frame[9] != 0) {
      LOG(ERROR) << "Unsupported ID3 frame in packed audio input.";
      return false;
    }
    const size_t frame_size = ReadSynchsafe(frame + 4);
    if (frame_size > tag_size - position - kId3FrameHeaderSize) {
      LOG(ERROR) << "Invalid ID3 frame length in packed audio input.";
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
          LOG(ERROR) << "Invalid packed audio transport timestamp.";
          return false;
        }
        uint64_t raw_timestamp;
        if (!reader.Read8(&raw_timestamp) ||
            raw_timestamp > static_cast<uint64_t>(kTimestampMask)) {
          LOG(ERROR) << "Invalid packed audio transport timestamp range.";
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
        if (encrypted || !reader.Read4(&format) ||
            (format != FOURCC_zac3 && format != FOURCC_zec3 &&
             format != FOURCC_zaac && format != FOURCC_zach &&
             format != FOURCC_zacp) ||
            !reader.SkipBytes(2) || !reader.Read1(&version) || version != 1 ||
            !reader.Read1(&setup_size) ||
            reader.size() - reader.pos() != setup_size) {
          LOG(ERROR) << "Unsupported packed audio setup.";
          return false;
        }
        audio_type = format;
        if (format != FOURCC_zac3) {
          setup_config.assign(data + reader.pos(), data + data_size);
          if (format == FOURCC_zec3 &&
              (setup_config.size() < 5 || (setup_config[1] & 7) != 0 ||
               ((setup_config[4] >> 1) & 15) > 8 ||
               GetEc3NumChannels(setup_config) == 0)) {
            LOG(ERROR)
                << "Invalid E-AC-3 setup or multiple independent programs.";
            return false;
          }
          if (setup_config.empty() ||
              (initialized_ && (audio_type_ != format ||
                                setup_config != audio_config_))) {
            LOG(ERROR) << "Invalid or changed packed audio configuration.";
            return false;
          }
        }
        encrypted = true;
      }
    }
    position += kId3FrameHeaderSize + frame_size;
  }
  if (!found_timestamp) {
    LOG(ERROR) << "Packed audio segment is missing its ID3 timestamp.";
    return false;
  }
  if (last_emitted_timestamp_ != kNoTimestamp &&
      timestamp <= last_emitted_timestamp_) {
    LOG(ERROR) << "Packed audio segment timestamp moves backwards.";
    return false;
  }

  if (encrypted) {
    if (initialized_ && audio_type_ != audio_type) {
      LOG(ERROR) << "Packed audio codec changed mid-stream.";
      return false;
    }
    if (!decryption_key_source_) {
      LOG(ERROR) << "Encrypted packed audio requires a key source.";
      return false;
    }
    EncryptionKey key;
    const Status status = decryption_key_source_->GetKey(std::string(), &key);
    if (!status.ok()) {
      LOG(ERROR) << "Unable to retrieve packed audio decryption key: "
                 << status.ToString();
      return false;
    }
    if (!key.iv.empty() && key.iv.size() != 16) {
      LOG(ERROR) << "Packed audio IV must contain 16 bytes when supplied.";
      return false;
    }
    if (audio_type != FOURCC_zac3 && key.iv.empty()) {
      LOG(ERROR) << "Encrypted packed audio requires an explicit 16-byte IV.";
      return false;
    }
    if (key.key != decryption_key_ || !key.iv.empty())
      recovered_iv_.clear();
    decryption_key_ = key.key;
    recover_missing_iv_ = key.iv.empty();
    if (recover_missing_iv_)
      key.iv =
          recovered_iv_.empty() ? std::vector<uint8_t>(16, 0) : recovered_iv_;
    decryptor_ = std::make_unique<AesCbcDecryptor>(
        kNoPadding, audio_type == FOURCC_zec3 ? AesCryptor::kDontUseConstantIv
                                              : AesCryptor::kUseConstantIv);
    if (!decryptor_->InitializeWithIv(key.key, key.iv)) {
      LOG(ERROR) << "Unable to initialize packed audio decryptor.";
      return false;
    }
  } else {
    decryptor_.reset();
    decryption_key_.clear();
    recovered_iv_.clear();
    recover_missing_iv_ = false;
  }

  buffer_position_ += tag_size;
  next_timestamp_ = timestamp;
  if (timestamp_helper_)
    timestamp_helper_->SetBaseTimestamp(timestamp);
  segment_is_encrypted_ = encrypted;
  if (audio_type != 0 && audio_type != FOURCC_zac3) {
    audio_config_ = std::move(setup_config);
    if (audio_type == FOURCC_zec3)
      ec3_expected_dependents_ = (audio_config_[4] >> 1) & 15;
    audio_type_ = audio_type;
  }
  have_segment_ = true;
  return true;
}

bool PackedAudioParser::ParseAc3Frame() {
  if (!have_segment_) {
    LOG(ERROR) << "Packed AC-3 audio is missing its leading ID3 tag.";
    return false;
  }
  if (audio_type_ != 0 && audio_type_ != FOURCC_zac3) {
    LOG(ERROR) << "AC-3 frame in a different packed audio stream.";
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

bool PackedAudioParser::ParseAacFrame() {
  if (!have_segment_ ||
      (audio_type_ != 0 && audio_type_ != FOURCC_zaac &&
       audio_type_ != FOURCC_zach && audio_type_ != FOURCC_zacp)) {
    LOG(ERROR) << "AAC frame without its ID3 segment or in a different stream.";
    return false;
  }

  const size_t available = buffer_.size() - buffer_position_;
  if (available < 7)
    return true;

  const uint8_t* data = buffer_.data() + buffer_position_;
  mp2t::AdtsHeader header;
  if (!header.IsSyncWord(data) || !header.Parse(data, available) ||
      header.GetFrameSize() <= header.GetHeaderSize()) {
    LOG(ERROR) << "Invalid packed AAC ADTS header.";
    return false;
  }
  if (available < header.GetFrameSize())
    return true;

  std::vector<uint8_t> adts_config;
  header.GetAudioSpecificConfig(&adts_config);
  if (!initialized_) {
    if (audio_config_.empty())
      audio_config_ = adts_config;

    AACAudioSpecificConfig config;
    if (!config.Parse(audio_config_)) {
      LOG(ERROR) << "Invalid packed AAC configuration.";
      return false;
    }

    BitReader reader(audio_config_.data(), audio_config_.size());
    uint8_t object_type;
    uint8_t frequency_index;
    bool short_frame;
    if (!reader.ReadBits(5, &object_type) ||
        !reader.ReadBits(4, &frequency_index) ||
        (frequency_index == 15 && !reader.SkipBits(24)) ||
        !reader.SkipBits(4)) {
      return false;
    }
    if (object_type == AACAudioSpecificConfig::AOT_SBR ||
        object_type == AACAudioSpecificConfig::AOT_PS) {
      if (!reader.ReadBits(4, &frequency_index) ||
          (frequency_index == 15 && !reader.SkipBits(24)) ||
          !reader.ReadBits(5, &object_type)) {
        return false;
      }
    }
    if (object_type < 1 || object_type > 4 ||
        !reader.ReadBits(1, &short_frame) || short_frame) {
      LOG(ERROR) << "Unsupported packed AAC frame configuration.";
      return false;
    }

    std::vector<uint8_t> expected_adts;
    mp2t::AdtsHeader expected_header;
    if (!config.ConvertToADTS(audio_config_.data(), 0, &expected_adts) ||
        !expected_header.Parse(expected_adts.data(), expected_adts.size())) {
      return false;
    }
    expected_header.GetAudioSpecificConfig(&aac_adts_config_);
    if (adts_config != aac_adts_config_) {
      LOG(ERROR) << "AAC frame does not match its setup.";
      return false;
    }

    if (audio_type_ == FOURCC_zach || audio_type_ == FOURCC_zacp)
      config.set_sbr_present(true);
    const uint8_t codec_object_type = static_cast<uint8_t>(
        audio_type_ == FOURCC_zacp ? AACAudioSpecificConfig::AOT_PS
                                  : config.GetAudioObjectType());
    std::shared_ptr<StreamInfo> stream(new AudioStreamInfo(
        kPackedAudioTrackId, kPackedAudioTimescale, kInfiniteDuration,
        kCodecAAC, AudioStreamInfo::GetCodecString(kCodecAAC, codec_object_type),
        audio_config_.data(), audio_config_.size(), 16, config.GetNumChannels(),
        config.GetSamplesPerSecond(), 0, 0, 0, 0, "und", false));
    if (!stream->IsValidConfig())
      return false;

    if (init_cb_)
      init_cb_({stream});
    timestamp_helper_ = std::make_unique<AudioTimestampHelper>(
        kPackedAudioTimescale, header.GetSamplingFrequency());
    timestamp_helper_->SetBaseTimestamp(next_timestamp_);
    if (audio_type_ == 0)
      audio_type_ = FOURCC_zaac;
    initialized_ = true;
  } else if (adts_config != aac_adts_config_) {
    LOG(ERROR) << "Packed AAC frame configuration changed.";
    return false;
  }

  std::vector<uint8_t> audio(data + header.GetHeaderSize(),
                             data + header.GetFrameSize());
  if (segment_is_encrypted_ && audio.size() > 16) {
    const size_t encrypted_size = ((audio.size() - 16) / 16) * 16;
    if (encrypted_size > 0 &&
        (!decryptor_ || !decryptor_->Crypt(audio.data() + 16, encrypted_size,
                                           audio.data() + 16))) {
      return false;
    }
  }

  const int64_t duration = timestamp_helper_->GetFrameDuration(1024);
  const int64_t timestamp = timestamp_helper_->GetTimestamp();
  std::shared_ptr<MediaSample> sample =
      MediaSample::CopyFrom(audio.data(), audio.size(), true);
  sample->set_dts(timestamp);
  sample->set_pts(timestamp);
  sample->set_duration(duration);
  if (duration <= 0 || !new_media_sample_cb_ ||
      !new_media_sample_cb_(kPackedAudioTrackId, std::move(sample))) {
    LOG(ERROR) << "Packed AAC sample callback rejected a frame.";
    return false;
  }

  timestamp_helper_->AddFrames(1024);
  next_timestamp_ = timestamp_helper_->GetTimestamp();
  last_emitted_timestamp_ = timestamp;
  buffer_position_ += header.GetFrameSize();
  return true;
}

bool PackedAudioParser::ParseEc3Frame() {
  if (!have_segment_ || audio_type_ != FOURCC_zec3 || audio_config_.empty()) {
    LOG(ERROR) << "Packed E-AC-3 requires ID3 zec3 setup.";
    return false;
  }

  const size_t available = buffer_.size() - buffer_position_;
  if (available < 6)
    return true;

  const uint8_t* data = buffer_.data() + buffer_position_;
  const uint8_t stream_type = data[2] >> 6;
  const uint8_t substream_id = (data[2] >> 3) & 7;
  const size_t frame_size = ((((data[2] & 7) << 8) | data[3]) + 1) * 2;
  const uint8_t fscod = data[4] >> 6;
  const uint8_t rate_code = (data[4] >> 4) & 3;
  const uint8_t bsid = data[5] >> 3;
  constexpr uint32_t sample_rates[] = {48000, 44100, 32000};
  constexpr uint8_t block_counts[] = {1, 2, 3, 6};
  if (data[0] != 0x0b || data[1] != 0x77 || stream_type == 3 ||
      frame_size < kAc3LeadingClearBytes || bsid < 11 || bsid > 16 ||
      (fscod == 3 && rate_code == 3)) {
    LOG(ERROR) << "Invalid E-AC-3 syncframe in packed audio input.";
    return false;
  }
  if (available < frame_size)
    return true;
  const uint32_t sample_rate =
      fscod == 3 ? sample_rates[rate_code] / 2 : sample_rates[fscod];
  const uint8_t blocks = fscod == 3 ? 6 : block_counts[rate_code];

  if (stream_type != 1) {
    if (substream_id != 0 ||
        (!ec3_frame_.empty() && ec3_dependents_ != ec3_expected_dependents_) ||
        ec3_blocks_ + blocks > 6) {
      LOG(ERROR)
          << "Unsupported E-AC-3 program or incomplete dependent substreams.";
      return false;
    }
    if (fscod != (audio_config_[2] >> 6) ||
        bsid != ((audio_config_[2] >> 1) & 31) ||
        (data[4] & 15) != (audio_config_[3] & 15) ||
        (initialized_ && sample_rate != ec3_sampling_frequency_)) {
      LOG(ERROR) << "E-AC-3 frame does not match its dec3 configuration.";
      return false;
    }
    if (!initialized_) {
      const size_t channels = GetEc3NumChannels(audio_config_);
      std::shared_ptr<StreamInfo> stream(new AudioStreamInfo(
          kPackedAudioTrackId, kPackedAudioTimescale, kInfiniteDuration,
          kCodecEAC3, AudioStreamInfo::GetCodecString(kCodecEAC3, 0),
          audio_config_.data(), audio_config_.size(), 16,
          static_cast<uint8_t>(channels), sample_rate, 0, 0, 0, 0, "und",
          false));
      if (!stream->IsValidConfig()) {
        LOG(ERROR) << "Invalid E-AC-3 stream configuration.";
        return false;
      }
      if (init_cb_)
        init_cb_({stream});
      timestamp_helper_ = std::make_unique<AudioTimestampHelper>(
          kPackedAudioTimescale, sample_rate);
      timestamp_helper_->SetBaseTimestamp(next_timestamp_);
      ec3_sampling_frequency_ = sample_rate;
      initialized_ = true;
    }
    ec3_blocks_ += blocks;
    ec3_frame_blocks_ = blocks;
    ec3_dependents_ = 0;
  } else {
    if (ec3_frame_.empty() || ec3_dependents_ >= ec3_expected_dependents_ ||
        substream_id != ec3_dependents_ || blocks != ec3_frame_blocks_ ||
        sample_rate != ec3_sampling_frequency_) {
      LOG(ERROR)
          << "Orphan, out-of-order or mismatched E-AC-3 dependent syncframe.";
      return false;
    }
    ++ec3_dependents_;
  }

  ec3_frame_.insert(ec3_frame_.end(), data, data + frame_size);
  buffer_position_ += frame_size;
  return ec3_blocks_ != 6 || ec3_dependents_ != ec3_expected_dependents_ ||
         EmitEc3Sample();
}

bool PackedAudioParser::EmitEc3Sample() {
  if (segment_is_encrypted_) {
    if (!decryptor_ || !decryptor_->SetIv(decryptor_->iv()))
      return false;

    size_t offset = 0;
    while (offset < ec3_frame_.size()) {
      uint8_t* frame = ec3_frame_.data() + offset;
      const size_t size = ((((frame[2] & 7) << 8) | frame[3]) + 1) * 2;
      const size_t encrypted_size = ((size - kAc3LeadingClearBytes) / 16) * 16;
      if (encrypted_size > 0 &&
          !decryptor_->Crypt(frame + kAc3LeadingClearBytes, encrypted_size,
                             frame + kAc3LeadingClearBytes))
        return false;
      if (Ac3Crc(frame + 2, size - 2) != 0) {
        LOG(ERROR)
            << "Packed E-AC-3 CRC mismatch after decryption. Check key and IV.";
        return false;
      }
      offset += size;
    }
  }

  const int64_t duration = timestamp_helper_->GetFrameDuration(1536);
  const int64_t timestamp = timestamp_helper_->GetTimestamp();
  std::shared_ptr<MediaSample> sample =
      MediaSample::CopyFrom(ec3_frame_.data(), ec3_frame_.size(), true);
  sample->set_dts(timestamp);
  sample->set_pts(timestamp);
  sample->set_duration(duration);
  if (duration <= 0 || !new_media_sample_cb_ ||
      !new_media_sample_cb_(kPackedAudioTrackId, std::move(sample))) {
    LOG(ERROR) << "Packed E-AC-3 sample callback rejected an access unit.";
    return false;
  }
  timestamp_helper_->AddFrames(1536);
  next_timestamp_ = timestamp_helper_->GetTimestamp();
  last_emitted_timestamp_ = timestamp;
  ec3_frame_.clear();
  ec3_blocks_ = 0;
  ec3_frame_blocks_ = 0;
  ec3_dependents_ = 0;
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
  audio_type_ = FOURCC_zac3;
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
  if (!decryptor_->Crypt(frame->data() + kAc3LeadingClearBytes, encrypted_size,
                         frame->data() + kAc3LeadingClearBytes))
    return false;
  if (recover_missing_iv_) {
    if (recovered_iv_.empty()) {
      if (!RecoverAc3Iv(frame, &recovered_iv_) ||
          !decryptor_->SetIv(recovered_iv_)) {
        LOG(ERROR) << "Cannot recover missing packed AC-3 IV from the first "
                      "frame: no matching coupling pattern with valid CRCs. "
                      "Check the key or provide an explicit IV.";
        return false;
      }
      LOG(WARNING) << "Recovered missing packed AC-3 IV from a repeated "
                      "coupling pattern and CRCs; using best-effort recovery.";
    } else if (!HasValidAc3Crc(*frame)) {
      LOG(ERROR) << "Packed AC-3 CRC mismatch after IV recovery.";
      return false;
    }
  }
  return true;
}

}  // namespace media
}  // namespace shaka
