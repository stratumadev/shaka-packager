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

TEST(PackedAudioParserTest, RejectsEncryptedAc3WithoutAnExplicitIv) {
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
