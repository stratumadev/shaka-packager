// Copyright 2026 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <packager/media/formats/packed_audio/packed_audio_parser.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <packager/file.h>
#include <packager/media/base/aes_encryptor.h>
#include <packager/media/base/buffer_writer.h>
#include <packager/media/base/id3_tag.h>
#include <packager/media/base/media_sample.h>
#include <packager/media/base/raw_key_source.h>
#include <packager/media/base/stream_info.h>
#include <packager/media/formats/mp4/mp4_media_parser.h>
#include <packager/media/formats/packed_audio/packed_audio_constants.h>
#include <packager/media/test/test_data_util.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace shaka {
namespace media {
namespace {

std::vector<uint8_t> MakeAc3Frame(uint8_t sample_rate_code = 0) {
  // A 48-kHz, 32-kbit/s, stereo AC-3 frame. frmsizecod=0 makes it 128 bytes.
  std::vector<uint8_t> frame(sample_rate_code == 1 ? 138 : 128, 0);
  frame[0] = 0x0B;
  frame[1] = 0x77;
  frame[4] = sample_rate_code << 6;
  frame[5] = 0x40;  // bsid = 8.
  frame[6] = 0x40;  // acmod = 2 (stereo).
  return frame;
}

std::vector<uint8_t> MakePackedAc3Segment(const std::string& audio_description,
                                          int64_t transport_timestamp = 90000) {
  BufferWriter timestamp_data;
  timestamp_data.AppendInt(static_cast<uint64_t>(transport_timestamp));

  Id3Tag tag;
  tag.AddPrivateFrame(
      kTimestampOwnerIdentifier,
      std::string(reinterpret_cast<const char*>(timestamp_data.Buffer()),
                  timestamp_data.Size()));
  if (!audio_description.empty())
    tag.AddPrivateFrame(kAudioDescriptionOwnerIdentifier, audio_description);

  BufferWriter segment;
  EXPECT_TRUE(tag.WriteToBuffer(&segment));
  const std::vector<uint8_t> frame = MakeAc3Frame();
  segment.AppendArray(frame.data(), frame.size());

  return std::vector<uint8_t>(segment.Buffer(),
                              segment.Buffer() + segment.Size());
}

std::vector<uint8_t> MakeClearPackedAc3SegmentWithFrames(
    int64_t timestamp,
    const std::vector<std::vector<uint8_t>>& frames) {
  BufferWriter timestamp_data;
  timestamp_data.AppendInt(static_cast<uint64_t>(timestamp));
  Id3Tag tag;
  tag.AddPrivateFrame(
      kTimestampOwnerIdentifier,
      std::string(reinterpret_cast<const char*>(timestamp_data.Buffer()),
                  timestamp_data.Size()));
  BufferWriter segment;
  EXPECT_TRUE(tag.WriteToBuffer(&segment));
  for (const std::vector<uint8_t>& frame : frames)
    segment.AppendArray(frame.data(), frame.size());
  return std::vector<uint8_t>(segment.Buffer(),
                              segment.Buffer() + segment.Size());
}

void AppendId3Padding(std::vector<uint8_t>* segment, size_t padding_size) {
  ASSERT_GE(segment->size(), 10u);
  ASSERT_LT(padding_size, 128u);
  (*segment)[9] += static_cast<uint8_t>(padding_size);
  segment->insert(segment->begin() + 10 + ((*segment)[9] - padding_size),
                  padding_size, 0);
}

std::string MakeAudioDescription(const char* type) {
  const std::vector<uint8_t> frame = MakeAc3Frame();
  std::string description(type, 4);
  description.append("\0\0\1", 3);
  description.push_back(10);
  description.append(reinterpret_cast<const char*>(frame.data()), 10);
  return description;
}

class MockKeySource : public RawKeySource {
 public:
  MOCK_METHOD2(GetKey,
               Status(const std::string& stream_label, EncryptionKey* key));
};

uint16_t Ac3Crc(const uint8_t* data, size_t size) {
  uint16_t crc = 0;
  for (size_t i = 0; i < size; ++i) {
    crc ^= static_cast<uint16_t>(data[i]) << 8;
    for (int bit = 0; bit < 8; ++bit)
      crc = (crc << 1) ^ ((crc & 0x8000) ? 0x8005 : 0);
  }
  return crc;
}

void SetAc3Crc(std::vector<uint8_t>* frame) {
  const size_t split = ((frame->size() >> 2) + (frame->size() >> 4)) << 1;
  // Invert the suffix to find the required CRC state after the leading CRC1.
  uint16_t state = 0;
  for (size_t i = split; i > 4; --i) {
    for (int bit = 0; bit < 8; ++bit) {
      const bool high = state & 1;
      state = ((state ^ (high ? 0x8005 : 0)) >> 1) | (high ? 0x8000 : 0);
    }
    state ^= static_cast<uint16_t>((*frame)[i - 1]) << 8;
  }
  for (uint32_t crc = 0; crc <= 0xffff; ++crc) {
    (*frame)[2] = crc >> 8;
    (*frame)[3] = crc;
    if (Ac3Crc(frame->data() + 2, 2) == state)
      break;
  }
  const uint16_t crc2 =
      Ac3Crc(frame->data() + split, frame->size() - split - 2);
  (*frame)[frame->size() - 2] = crc2 >> 8;
  frame->back() = crc2;
  EXPECT_EQ(0, Ac3Crc(frame->data() + 2, split - 2));
  EXPECT_EQ(0, Ac3Crc(frame->data() + split, frame->size() - split));
}

std::vector<uint8_t> MakeRecoverableAc3Frame(uint8_t coordinate = 0x31,
                                             bool dynamic_range = false) {
  std::vector<uint8_t> frame(128, 0);
  size_t position = 0;
  const auto write = [&frame, &position](uint32_t value, size_t count) {
    for (size_t bit = count; bit > 0; --bit, ++position)
      frame[position / 8] |= ((value >> (bit - 1)) & 1) << (7 - position % 8);
  };
  write(0x0b77, 16);
  write(0, 16);  // CRC1, filled below.
  write(0, 8);   // 48 kHz, 32 kbit/s.
  write(8, 5);   // bsid.
  write(0, 3);   // bsmod.
  write(7, 3);   // Five full-bandwidth channels.
  write(0, 4);   // Center and surround mix levels.
  write(1, 1);   // LFE.
  write(27, 5);
  write(1, 1);  // Compression word present.
  write(255, 8);
  write(0, 2);   // No language or production information.
  write(3, 2);   // Copyright and original.
  write(0, 3);   // No timecodes or additional BSI.
  write(0, 5);   // Block switching.
  write(31, 5);  // Dither flags.
  write(dynamic_range, 1);
  if (dynamic_range)
    write(0, 8);
  write(3, 2);   // Coupling strategy present and enabled.
  write(31, 5);  // All channels coupled.
  write(6, 4);
  write(10, 4);
  write(0x16, 6);  // Four coupling bands.
  for (int channel = 0; channel < 5; ++channel) {
    write(1, 1);
    write(2, 2);  // Master coordinate, deliberately not the Apple sample value.
    for (int band = 0; band < 4; ++band)
      write(coordinate, 8);
  }
  SetAc3Crc(&frame);
  return frame;
}

class PackedAudioIvRecoveryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    for (int i = 0; i < 16; ++i) {
      key_.key.push_back(7 + 13 * i);
      iv_.push_back(251 - 7 * i);
    }
    EXPECT_CALL(key_source_, GetKey(std::string(), _))
        .WillRepeatedly(Invoke([this](const std::string&, EncryptionKey* key) {
          *key = key_;
          return Status::OK;
        }));
    Init();
  }

  void Init() {
    parser_.Init(
        MediaParser::InitCB(),
        [this](uint32_t, std::shared_ptr<MediaSample> sample) {
          samples_.emplace_back(sample->data(),
                                sample->data() + sample->data_size());
          return true;
        },
        MediaParser::NewTextSampleCB(), &key_source_);
  }

  std::vector<uint8_t> Segment(const std::vector<uint8_t>& frame,
                               int64_t timestamp = 90000) {
    std::vector<uint8_t> segment =
        MakePackedAc3Segment(MakeAudioDescription("zac3"), timestamp);
    segment.resize(segment.size() - MakeAc3Frame().size());
    std::vector<uint8_t> encrypted(frame);
    AesCbcEncryptor encryptor(kNoPadding, AesCryptor::kUseConstantIv);
    EXPECT_TRUE(encryptor.InitializeWithIv(key_.key, iv_));
    EXPECT_TRUE(encryptor.Crypt(encrypted.data() + 16,
                                ((encrypted.size() - 16) / 16) * 16,
                                encrypted.data() + 16));
    segment.insert(segment.end(), encrypted.begin(), encrypted.end());
    return segment;
  }

  PackedAudioParser parser_;
  MockKeySource key_source_;
  EncryptionKey key_;
  std::vector<uint8_t> iv_;
  std::vector<std::vector<uint8_t>> samples_;
};

TEST_F(PackedAudioIvRecoveryTest, RecoversArbitraryIvAcrossOneByteChunks) {
  for (uint8_t coordinate : {0x31, 0x78, 0xf0}) {
    Init();
    samples_.clear();
    const auto frame = MakeRecoverableAc3Frame(coordinate, coordinate == 0x78);
    const auto segment = Segment(frame);
    for (size_t i = 0; i < segment.size(); ++i)
      ASSERT_TRUE(parser_.Parse(segment.data() + i, 1));
    ASSERT_TRUE(parser_.Flush());
    ASSERT_EQ(1u, samples_.size());
    EXPECT_EQ(frame, samples_[0]);
  }
}

TEST_F(PackedAudioIvRecoveryTest, ReusesRecoveredIvForSameKeyAcrossId3Tags) {
  const auto first_frame = MakeRecoverableAc3Frame();
  auto second_frame = first_frame;
  second_frame[20] ^= 4;  // The later frame has no uniform coordinate pattern.
  SetAc3Crc(&second_frame);
  auto segment = Segment(first_frame);
  const auto second = Segment(second_frame, 92880);
  segment.insert(segment.end(), second.begin(), second.end());
  ASSERT_TRUE(parser_.Parse(segment.data(), static_cast<int>(segment.size())));
  ASSERT_TRUE(parser_.Flush());
  EXPECT_EQ((std::vector<std::vector<uint8_t>>{first_frame, second_frame}),
            samples_);
}

TEST_F(PackedAudioIvRecoveryTest, Recovers44100HzFrameWithClearTrailingBytes) {
  auto frame = MakeRecoverableAc3Frame();
  frame.resize(138);
  frame[4] = 0x40;
  frame[130] = 0xa5;
  SetAc3Crc(&frame);
  const auto segment = Segment(frame);
  ASSERT_TRUE(parser_.Parse(segment.data(), static_cast<int>(segment.size())));
  ASSERT_TRUE(parser_.Flush());
  ASSERT_EQ(1u, samples_.size());
  EXPECT_EQ(frame, samples_[0]);
}

TEST_F(PackedAudioIvRecoveryTest, ExplicitIvOverridesPreviouslyRecoveredIv) {
  const auto first = Segment(MakeRecoverableAc3Frame());
  ASSERT_TRUE(parser_.Parse(first.data(), static_cast<int>(first.size())));
  iv_[0] ^= 0x55;
  key_.iv = iv_;
  auto frame = MakeRecoverableAc3Frame();
  frame[20] ^= 4;
  SetAc3Crc(&frame);
  const auto second = Segment(frame, 92880);
  ASSERT_TRUE(parser_.Parse(second.data(), static_cast<int>(second.size())));
  ASSERT_TRUE(parser_.Flush());
  ASSERT_EQ(2u, samples_.size());
  EXPECT_EQ(frame, samples_[1]);
}

TEST_F(PackedAudioIvRecoveryTest, RejectsMissingPatternWithoutEmittingAudio) {
  auto frame = MakeRecoverableAc3Frame();
  frame[15] ^= 1;
  SetAc3Crc(&frame);
  const auto segment = Segment(frame);
  EXPECT_FALSE(parser_.Parse(segment.data(), static_cast<int>(segment.size())));
  EXPECT_TRUE(samples_.empty());
}

TEST_F(PackedAudioIvRecoveryTest, RejectsWrongKeyWithoutEmittingAudio) {
  const auto segment = Segment(MakeRecoverableAc3Frame());
  key_.key[0] ^= 1;
  EXPECT_FALSE(parser_.Parse(segment.data(), static_cast<int>(segment.size())));
  EXPECT_TRUE(samples_.empty());
}

TEST_F(PackedAudioIvRecoveryTest, RejectsCandidateWithInvalidCrc1) {
  auto segment = Segment(MakeRecoverableAc3Frame());
  segment[segment.size() - 128 + 2] ^= 1;
  EXPECT_FALSE(parser_.Parse(segment.data(), static_cast<int>(segment.size())));
  EXPECT_TRUE(samples_.empty());
}

TEST_F(PackedAudioIvRecoveryTest, RejectsCorruptionAfterIvRecovery) {
  const auto first = Segment(MakeRecoverableAc3Frame());
  ASSERT_TRUE(parser_.Parse(first.data(), static_cast<int>(first.size())));
  auto second = Segment(MakeRecoverableAc3Frame(), 92880);
  second.back() ^= 1;
  EXPECT_FALSE(parser_.Parse(second.data(), static_cast<int>(second.size())));
  EXPECT_EQ(1u, samples_.size());
}

TEST_F(PackedAudioIvRecoveryTest, DoesNotReuseIvAfterFlushOrInit) {
  for (bool reinitialize : {false, true}) {
    Init();
    const auto first = Segment(MakeRecoverableAc3Frame());
    ASSERT_TRUE(parser_.Parse(first.data(), static_cast<int>(first.size())));
    if (reinitialize)
      Init();
    else
      ASSERT_TRUE(parser_.Flush());
    auto frame = MakeRecoverableAc3Frame();
    frame[15] ^= 1;
    SetAc3Crc(&frame);
    const auto second = Segment(frame, 0);
    EXPECT_FALSE(parser_.Parse(second.data(), static_cast<int>(second.size())));
  }
}

TEST_F(PackedAudioIvRecoveryTest, RecoversAgainWhenActualKeyChanges) {
  const auto first = Segment(MakeRecoverableAc3Frame());
  ASSERT_TRUE(parser_.Parse(first.data(), static_cast<int>(first.size())));
  key_.key[0] ^= 1;
  iv_[1] ^= 0x3c;
  const auto frame = MakeRecoverableAc3Frame(0x62);
  const auto second = Segment(frame, 92880);
  ASSERT_TRUE(parser_.Parse(second.data(), static_cast<int>(second.size())));
  ASSERT_TRUE(parser_.Flush());
  ASSERT_EQ(2u, samples_.size());
  EXPECT_EQ(frame, samples_[1]);
}

TEST(PackedAudioParserTest, EmitsClearAc3FrameAcrossInputChunks) {
  const std::vector<uint8_t> segment = MakePackedAc3Segment("");
  const std::vector<uint8_t> expected_frame = MakeAc3Frame();

  PackedAudioParser parser;
  std::vector<std::shared_ptr<StreamInfo>> streams;
  std::vector<std::shared_ptr<MediaSample>> samples;
  parser.Init(
      [&streams](const std::vector<std::shared_ptr<StreamInfo>>& value) {
        streams = value;
      },
      [&samples](uint32_t, std::shared_ptr<MediaSample> sample) {
        samples.push_back(std::move(sample));
        return true;
      },
      MediaParser::NewTextSampleCB(), nullptr);

  for (size_t index = 0; index < segment.size(); ++index)
    ASSERT_TRUE(parser.Parse(segment.data() + index, 1));
  ASSERT_TRUE(parser.Flush());
  EXPECT_TRUE(parser.Flush());

  ASSERT_EQ(1u, streams.size());
  EXPECT_EQ(kCodecAC3, streams[0]->codec());
  ASSERT_EQ(1u, samples.size());
  EXPECT_EQ(90000, samples[0]->pts());
  EXPECT_EQ(2880, samples[0]->duration());
  ASSERT_EQ(expected_frame.size(), samples[0]->data_size());
  EXPECT_EQ(0, std::memcmp(expected_frame.data(), samples[0]->data(),
                           expected_frame.size()));
}

TEST(PackedAudioParserTest, AcceptsShortZeroPaddingAfterId3Frames) {
  std::vector<uint8_t> segment = MakePackedAc3Segment("");
  AppendId3Padding(&segment, 3);

  PackedAudioParser parser;
  size_t samples = 0;
  parser.Init(
      MediaParser::InitCB(),
      [&samples](uint32_t, std::shared_ptr<MediaSample>) {
        ++samples;
        return true;
      },
      MediaParser::NewTextSampleCB(), nullptr);

  ASSERT_TRUE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
  ASSERT_TRUE(parser.Flush());
  EXPECT_EQ(1u, samples);
}

TEST(PackedAudioParserTest, RejectsTruncatedAc3FrameWhenFlushed) {
  std::vector<uint8_t> segment = MakePackedAc3Segment("");
  segment.pop_back();

  PackedAudioParser parser;
  parser.Init(MediaParser::InitCB(), MediaParser::NewMediaSampleCB(),
              MediaParser::NewTextSampleCB(), nullptr);

  ASSERT_TRUE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
  EXPECT_FALSE(parser.Flush());
}

TEST(PackedAudioParserTest, KeepsRounded44100HzDurationsCumulative) {
  const std::vector<uint8_t> frame = MakeAc3Frame(1);
  const std::vector<uint8_t> segment =
      MakeClearPackedAc3SegmentWithFrames(90000, {frame, frame});

  PackedAudioParser parser;
  std::vector<std::shared_ptr<MediaSample>> samples;
  parser.Init(
      MediaParser::InitCB(),
      [&samples](uint32_t, std::shared_ptr<MediaSample> sample) {
        samples.push_back(std::move(sample));
        return true;
      },
      MediaParser::NewTextSampleCB(), nullptr);

  ASSERT_TRUE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
  ASSERT_TRUE(parser.Flush());
  ASSERT_EQ(2u, samples.size());
  EXPECT_EQ(90000, samples[0]->pts());
  EXPECT_EQ(3134, samples[0]->duration());
  EXPECT_EQ(93134, samples[1]->pts());
  EXPECT_EQ(3135, samples[1]->duration());
}

TEST(PackedAudioParserTest, RejectsSegmentTimestampThatMovesBackwards) {
  std::vector<uint8_t> segment = MakePackedAc3Segment("", 90000);
  const std::vector<uint8_t> second = MakePackedAc3Segment("", 90000);
  segment.insert(segment.end(), second.begin(), second.end());

  PackedAudioParser parser;
  parser.Init(
      MediaParser::InitCB(),
      [](uint32_t, std::shared_ptr<MediaSample>) { return true; },
      MediaParser::NewTextSampleCB(), nullptr);

  EXPECT_FALSE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
}

TEST(PackedAudioParserTest, AcceptsEarlierSeekPointAfterFlush) {
  const std::vector<uint8_t> segment = MakePackedAc3Segment("", 90000);
  const std::vector<uint8_t> earlier = MakePackedAc3Segment("", 0);

  PackedAudioParser parser;
  size_t stream_info_calls = 0;
  std::vector<std::shared_ptr<MediaSample>> samples;
  parser.Init(
      [&stream_info_calls](const std::vector<std::shared_ptr<StreamInfo>>&) {
        ++stream_info_calls;
      },
      [&samples](uint32_t, std::shared_ptr<MediaSample> sample) {
        samples.push_back(std::move(sample));
        return true;
      },
      MediaParser::NewTextSampleCB(), nullptr);

  ASSERT_TRUE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
  ASSERT_TRUE(parser.Flush());
  ASSERT_TRUE(parser.Parse(earlier.data(), static_cast<int>(earlier.size())));
  ASSERT_TRUE(parser.Flush());
  EXPECT_EQ(1u, stream_info_calls);
  ASSERT_EQ(2u, samples.size());
  EXPECT_EQ(0, samples[1]->pts());
}

TEST(PackedAudioParserTest, UnwrapsThirtyThreeBitTimestampRollover) {
  std::vector<uint8_t> segment = MakePackedAc3Segment("", (1LL << 33) - 100);
  const std::vector<uint8_t> second = MakePackedAc3Segment("", 200);
  segment.insert(segment.end(), second.begin(), second.end());

  PackedAudioParser parser;
  std::vector<std::shared_ptr<MediaSample>> samples;
  parser.Init(
      MediaParser::InitCB(),
      [&samples](uint32_t, std::shared_ptr<MediaSample> sample) {
        samples.push_back(std::move(sample));
        return true;
      },
      MediaParser::NewTextSampleCB(), nullptr);

  ASSERT_TRUE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
  ASSERT_TRUE(parser.Flush());
  ASSERT_EQ(2u, samples.size());
  EXPECT_LT(samples[0]->pts(), samples[1]->pts());
  EXPECT_EQ((1LL << 33) + 200, samples[1]->pts());
}

TEST(PackedAudioParserTest, RejectsEncryptedAc3WithoutIvOrRecoverablePattern) {
  const std::vector<uint8_t> segment =
      MakePackedAc3Segment(MakeAudioDescription("zac3"));

  PackedAudioParser parser;
  MockKeySource key_source;
  EncryptionKey key;
  key.key.assign(16, 1);
  EXPECT_CALL(key_source, GetKey(std::string(), _))
      .WillOnce(DoAll(SetArgPointee<1>(key), Return(Status::OK)));
  parser.Init(MediaParser::InitCB(), MediaParser::NewMediaSampleCB(),
              MediaParser::NewTextSampleCB(), &key_source);

  EXPECT_FALSE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
}

TEST(PackedAudioParserTest, RejectsUnsupportedEac3AudioDescription) {
  const std::vector<uint8_t> segment =
      MakePackedAc3Segment(MakeAudioDescription("zec3"));

  PackedAudioParser parser;
  parser.Init(MediaParser::InitCB(), MediaParser::NewMediaSampleCB(),
              MediaParser::NewTextSampleCB(), nullptr);

  EXPECT_FALSE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
}

TEST(PackedAudioParserTest, RejectsEncryptedAc3WithAnEightByteIv) {
  const std::vector<uint8_t> segment =
      MakePackedAc3Segment(MakeAudioDescription("zac3"));

  PackedAudioParser parser;
  MockKeySource key_source;
  EncryptionKey key;
  key.key.assign(16, 1);
  key.iv.assign(8, 2);
  EXPECT_CALL(key_source, GetKey(std::string(), _))
      .WillOnce(DoAll(SetArgPointee<1>(key), Return(Status::OK)));
  parser.Init(MediaParser::InitCB(), MediaParser::NewMediaSampleCB(),
              MediaParser::NewTextSampleCB(), &key_source);

  EXPECT_FALSE(parser.Parse(segment.data(), static_cast<int>(segment.size())));
}

TEST(PackedAudioParserTest, DecryptsSegmentsToOriginalAc3Samples) {
  std::string packed_audio;
  for (int segment = 1; segment <= 3; ++segment) {
    std::string data;
    ASSERT_TRUE(File::ReadFileToString(
        GetAppTestDataFilePath("avc-ts-ac3-packed-audio-with-encryption/"
                               "bear-640x360-ac3-audio-" +
                               std::to_string(segment) + ".ac3")
            .string()
            .c_str(),
        &data));
    packed_audio += data;
  }
  std::string mp4_audio;
  ASSERT_TRUE(File::ReadFileToString(
      GetAppTestDataFilePath("avc-ac3-ts-to-mp4/bear-640x360-ac3-audio.mp4")
          .string()
          .c_str(),
      &mp4_audio));

  // Public key and IV used to generate the encrypted repository fixtures.
  EncryptionKey key;
  key.key = {0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
             0x30, 0x21, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
  key.iv = {0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
            0,    0,    0,    0,    0,    0,    0,    0};
  MockKeySource key_source;
  EXPECT_CALL(key_source, GetKey(std::string(), _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(key), Return(Status::OK)));

  PackedAudioParser packed_parser;
  mp4::MP4MediaParser mp4_parser;
  std::vector<std::vector<uint8_t>> decrypted;
  std::vector<std::vector<uint8_t>> expected;
  const auto init_cb = [](const std::vector<std::shared_ptr<StreamInfo>>&) {};
  packed_parser.Init(
      init_cb,
      [&decrypted](uint32_t, std::shared_ptr<MediaSample> sample) {
        decrypted.emplace_back(sample->data(),
                               sample->data() + sample->data_size());
        return true;
      },
      MediaParser::NewTextSampleCB(), &key_source);
  mp4_parser.Init(
      init_cb,
      [&expected](uint32_t, std::shared_ptr<MediaSample> sample) {
        expected.emplace_back(sample->data(),
                              sample->data() + sample->data_size());
        return true;
      },
      MediaParser::NewTextSampleCB(), nullptr);

  ASSERT_TRUE(
      packed_parser.Parse(reinterpret_cast<const uint8_t*>(packed_audio.data()),
                          static_cast<int>(packed_audio.size())));
  ASSERT_TRUE(packed_parser.Flush());
  ASSERT_TRUE(
      mp4_parser.Parse(reinterpret_cast<const uint8_t*>(mp4_audio.data()),
                       static_cast<int>(mp4_audio.size())));
  ASSERT_TRUE(mp4_parser.Flush());
  ASSERT_FALSE(expected.empty());
  EXPECT_EQ(expected, decrypted);
}

}  // namespace
}  // namespace media
}  // namespace shaka
