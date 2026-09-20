// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <packager/media/formats/mp2t/mp2t_media_parser.h>

#include <algorithm>
#include <functional>
#include <string>

#include <absl/log/log.h>
#include <gtest/gtest.h>

#include <packager/file.h>
#include <packager/macros/logging.h>
#include <packager/media/base/audio_stream_info.h>
#include <packager/media/base/buffer_writer.h>
#include <packager/media/base/media_sample.h>
#include <packager/media/base/raw_key_source.h>
#include <packager/media/base/stream_info.h>
#include <packager/media/base/timestamp.h>
#include <packager/media/base/video_stream_info.h>
#include <packager/media/codecs/nalu_reader.h>
#include <packager/media/formats/mp2t/mp2t_common.h>
#include <packager/media/formats/mp2t/ts_packet.h>
#include <packager/media/formats/mp4/mp4_media_parser.h>
#include <packager/media/test/test_data_util.h>

namespace shaka {
namespace media {
namespace mp2t {

class Mp2tMediaParserTest : public testing::Test {
 public:
  Mp2tMediaParserTest()
      : audio_frame_count_(0),
        video_frame_count_(0),
        video_min_dts_(kNoTimestamp),
        video_max_dts_(kNoTimestamp),
        video_min_pts_(kNoTimestamp),
        video_max_pts_(kNoTimestamp) {
    parser_.reset(new Mp2tMediaParser());
  }

 protected:
  typedef std::map<int, std::shared_ptr<StreamInfo>> StreamMap;

  std::unique_ptr<Mp2tMediaParser> parser_;
  StreamMap stream_map_;
  int audio_frame_count_;
  int video_frame_count_;
  int64_t video_min_dts_;
  int64_t video_max_dts_;
  int64_t video_min_pts_;
  int64_t video_max_pts_;

  bool AppendData(const uint8_t* data, size_t length) {
    return parser_->Parse(data, static_cast<int>(length));
  }

  bool AppendDataInPieces(const uint8_t* data,
                          size_t length,
                          size_t piece_size) {
    const uint8_t* start = data;
    const uint8_t* end = data + length;
    while (start < end) {
      size_t append_size = std::min(piece_size,
                                    static_cast<size_t>(end - start));
      if (!AppendData(start, append_size))
        return false;
      start += append_size;
    }
    return true;
  }

  void OnInit(const std::vector<std::shared_ptr<StreamInfo>>& stream_infos) {
    DVLOG(1) << "OnInit: " << stream_infos.size() << " streams.";
    for (const auto& stream_info : stream_infos) {
      DVLOG(1) << stream_info->ToString();
      stream_map_[stream_info->track_id()] = stream_info;
    }
  }

  bool OnNewSample(uint32_t track_id, std::shared_ptr<MediaSample> sample) {
    StreamMap::const_iterator stream = stream_map_.find(track_id);
    EXPECT_NE(stream_map_.end(), stream);
    if (stream != stream_map_.end()) {
      if (stream->second->stream_type() == kStreamAudio) {
        ++audio_frame_count_;
      } else if (stream->second->stream_type() == kStreamVideo) {
        ++video_frame_count_;
        if (video_min_dts_ == kNoTimestamp)
          video_min_dts_ = sample->dts();
        if (video_min_pts_ == kNoTimestamp || video_min_pts_ > sample->pts())
          video_min_pts_ = sample->pts();
        // Verify timestamps are increasing.
        if (video_max_dts_ == kNoTimestamp)
          video_max_dts_ = sample->dts();
        else if (video_max_dts_ >= sample->dts()) {
          LOG(ERROR) << "Video DTS not strictly increasing.";
          return false;
        }
        if (video_max_pts_ < sample->pts()) {
          video_max_pts_ = sample->pts();
        }
        video_max_dts_ = sample->dts();
      } else {
        LOG(ERROR) << "Missing StreamInfo for track ID " << track_id;
        return false;
      }
    }

    return true;
  }

  bool OnNewTextSample(uint32_t track_id, std::shared_ptr<TextSample> sample) {
    return false;
  }

  void InitializeParser() {
    parser_->Init(
        std::bind(&Mp2tMediaParserTest::OnInit, this, std::placeholders::_1),
        std::bind(&Mp2tMediaParserTest::OnNewSample, this,
                  std::placeholders::_1, std::placeholders::_2),
        std::bind(&Mp2tMediaParserTest::OnNewTextSample, this,
                  std::placeholders::_1, std::placeholders::_2),
        NULL);
  }

  bool ParseMpeg2TsFile(const std::string& filename, int append_bytes) {
    InitializeParser();

    std::vector<uint8_t> buffer = ReadTestDataFile(filename);
    if (buffer.empty())
      return false;

    return AppendDataInPieces(buffer.data(), buffer.size(), append_bytes);
  }
};

TEST_F(Mp2tMediaParserTest, UnalignedAppend17_H264) {
  // Test small, non-segment-aligned appends.
  ASSERT_TRUE(ParseMpeg2TsFile("bear-640x360.ts", 17));
  EXPECT_EQ(79, video_frame_count_);
  EXPECT_TRUE(parser_->Flush());
  EXPECT_EQ(82, video_frame_count_);
}

TEST_F(Mp2tMediaParserTest, UnalignedAppend512_H264) {
  // Test small, non-segment-aligned appends.
  ASSERT_TRUE(ParseMpeg2TsFile("bear-640x360.ts", 512));
  EXPECT_EQ(79, video_frame_count_);
  EXPECT_TRUE(parser_->Flush());
  EXPECT_EQ(82, video_frame_count_);
}

TEST_F(Mp2tMediaParserTest, UnalignedAppend17_H265) {
  // Test small, non-segment-aligned appends.
  ASSERT_TRUE(ParseMpeg2TsFile("bear-640x360-hevc.ts", 17));
  EXPECT_EQ(78, video_frame_count_);
  EXPECT_TRUE(parser_->Flush());
  EXPECT_EQ(82, video_frame_count_);
}

TEST_F(Mp2tMediaParserTest, UnalignedAppend512_H265) {
  // Test small, non-segment-aligned appends.
  ASSERT_TRUE(ParseMpeg2TsFile("bear-640x360-hevc.ts", 512));
  EXPECT_EQ(78, video_frame_count_);
  EXPECT_TRUE(parser_->Flush());
  EXPECT_EQ(82, video_frame_count_);
}

TEST_F(Mp2tMediaParserTest, TimestampWrapAround) {
  // "bear-640x360_ptszero_dtswraparound.ts" has been transcoded from
  // bear-640x360.mp4 by applying a time offset of 95442s (close to 2^33 /
  // 90000) which results in timestamp wrap around in the Mpeg2 TS stream.
  ASSERT_TRUE(ParseMpeg2TsFile("bear-640x360_ptswraparound.ts", 512));
  EXPECT_TRUE(parser_->Flush());
  EXPECT_EQ(82, video_frame_count_);
  EXPECT_LT(video_min_dts_, static_cast<int64_t>(1) << 33);
  EXPECT_GT(video_max_dts_, static_cast<int64_t>(1) << 33);
}

TEST_F(Mp2tMediaParserTest, PtsZeroDtsWrapAround) {
  // "bear-640x360.ts" has been transcoded from bear-640x360.mp4 by applying a
  // dts (close to 2^33 / 90000) and pts 1433 which results in dts
  // wrap around in the Mpeg2 TS stream but pts does not.
  ASSERT_TRUE(ParseMpeg2TsFile("bear-640x360_ptszero_dtswraparound.ts", 512));
  EXPECT_TRUE(parser_->Flush());
  EXPECT_EQ(64, video_frame_count_);
  // DTS was subjected to unroll
  EXPECT_LT(video_min_dts_, static_cast<int64_t>(1) << 33);
  EXPECT_GT(video_max_dts_, static_cast<int64_t>(1) << 33);
  // PTS was not subjected to unroll but was artificially unrolled to be close
  // to DTS
  EXPECT_GT(video_min_pts_, static_cast<int64_t>(1) << 33);
  EXPECT_GT(video_max_pts_, static_cast<int64_t>(1) << 33);
}

TEST_F(Mp2tMediaParserTest, PmtEsDescriptors) {
  //"bear-eng-visualy-impaired-audio.ts" consist of audio stream marked as
  // english audio with commentary for visualy impaired viewer and max
  // bitrate set to ~128kbps

  ParseMpeg2TsFile("bear-visualy-impaired-eng-audio.ts", 188);
  EXPECT_TRUE(parser_->Flush());
  EXPECT_STREQ("eng", stream_map_[257]->language().c_str());

  auto* audio_info = static_cast<AudioStreamInfo*>(stream_map_[257].get());
  EXPECT_EQ(131600, audio_info->max_bitrate());
}

class SampleAesKeySource : public RawKeySource {
 public:
  SampleAesKeySource() {
    // Public key and IV used by the repository's SAMPLE-AES fixtures.
    key.key = {0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
               0x30, 0x21, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    key.iv = {0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
              0,    0,    0,    0,    0,    0,    0,    0};
  }

  Status GetKey(const std::string& stream_label,
                EncryptionKey* output) override {
    EXPECT_TRUE(stream_label.empty());
    *output = key;
    return Status::OK;
  }

  EncryptionKey key;
};

class Mp2tSampleAesTest : public testing::Test {
 protected:
  void SetUp() override {
    for (int segment = 1; segment <= 3; ++segment) {
      std::string bytes;
      ASSERT_TRUE(File::ReadFileToString(
          GetAppTestDataFilePath("avc-ts-ac3-packed-audio-with-encryption/"
                                 "bear-640x360-ac3-video-" +
                                 std::to_string(segment) + ".ts")
              .string()
              .c_str(),
          &bytes));
      encrypted_ += bytes;
      if (segment == 1)
        clear_lead_size_ = bytes.size();
    }
  }

  bool ParseEncrypted(KeySource* key_source, size_t chunk_size) {
    Mp2tMediaParser parser;
    parser.Init([](const std::vector<std::shared_ptr<StreamInfo>>&) {},
                [this](uint32_t, std::shared_ptr<MediaSample> sample) {
                  samples_.emplace_back(sample->data(),
                                        sample->data() + sample->data_size());
                  return true;
                },
                [](uint32_t, std::shared_ptr<TextSample>) { return false; },
                key_source);
    for (size_t offset = 0; offset < encrypted_.size(); offset += chunk_size) {
      const size_t size = std::min(chunk_size, encrypted_.size() - offset);
      if (!parser.Parse(
              reinterpret_cast<const uint8_t*>(encrypted_.data() + offset),
              static_cast<int>(size)))
        return false;
    }
    return parser.Flush();
  }

  void ExpectOriginalSamples() {
    std::string bytes;
    ASSERT_TRUE(File::ReadFileToString(
        GetAppTestDataFilePath("avc-ac3-ts-to-mp4/"
                               "bear-640x360-ac3-video.mp4")
            .string()
            .c_str(),
        &bytes));
    mp4::MP4MediaParser parser;
    std::vector<std::vector<uint8_t>> expected;
    parser.Init([](const std::vector<std::shared_ptr<StreamInfo>>&) {},
                [&expected](uint32_t, std::shared_ptr<MediaSample> sample) {
                  expected.emplace_back(sample->data(),
                                        sample->data() + sample->data_size());
                  return true;
                },
                MediaParser::NewTextSampleCB(), nullptr);
    ASSERT_TRUE(parser.Parse(reinterpret_cast<const uint8_t*>(bytes.data()),
                             static_cast<int>(bytes.size())));
    ASSERT_TRUE(parser.Flush());
    ASSERT_FALSE(expected.empty());
    ASSERT_EQ(expected.size(), samples_.size());
    for (size_t i = 0; i < expected.size(); ++i)
      EXPECT_TRUE(expected[i] == samples_[i]) << "Sample " << i;
  }

  SampleAesKeySource key_source_;
  std::string encrypted_;
  std::vector<std::vector<uint8_t>> samples_;
  size_t clear_lead_size_ = 0;
};

TEST_F(Mp2tSampleAesTest, DecryptsAvcToOriginalSamples) {
  ASSERT_TRUE(ParseEncrypted(&key_source_, encrypted_.size()));
  ExpectOriginalSamples();
}

TEST_F(Mp2tSampleAesTest, DecryptsAcrossUnalignedPacketAndPesBoundaries) {
  ASSERT_TRUE(ParseEncrypted(&key_source_, 17));
  ExpectOriginalSamples();
}

TEST_F(Mp2tSampleAesTest, KeepsParameterSetsAcrossEncryptionTransition) {
  // Replace repeated SPS/PPS in the encrypted segments with valid filler NALs.
  // Keep packet lengths and timestamps intact; only the clear lead supplies
  // the decoder configuration needed for the rest of the stream.
  std::vector<uint8_t> elementary_stream;
  std::vector<size_t> source_offsets;
  const auto* bytes = reinterpret_cast<const uint8_t*>(encrypted_.data());
  int video_pid = -1;
  for (size_t offset = clear_lead_size_; offset + 188 <= encrypted_.size();
       offset += 188) {
    std::unique_ptr<TsPacket> packet(TsPacket::Parse(bytes + offset, 188));
    ASSERT_TRUE(packet);
    const uint8_t* payload = packet->payload();
    size_t skip = 0;
    if (packet->payload_unit_start_indicator()) {
      if (packet->payload_size() < 9 || payload[0] != 0 || payload[1] != 0 ||
          payload[2] != 1 || (payload[3] & 0xf0) != 0xe0)
        continue;
      video_pid = packet->pid();
      skip = 9 + payload[8];
    }
    if (packet->pid() != video_pid)
      continue;
    for (size_t i = skip; i < static_cast<size_t>(packet->payload_size());
         ++i) {
      elementary_stream.push_back(payload[i]);
      source_offsets.push_back(payload + i - bytes);
    }
  }
  NaluReader reader(Nalu::kH264, 0, elementary_stream.data(),
                    elementary_stream.size());
  Nalu nalu;
  size_t replaced = 0;
  while (reader.Advance(&nalu) == NaluReader::kOk) {
    if (nalu.type() != Nalu::H264_SPS && nalu.type() != Nalu::H264_PPS)
      continue;
    const size_t offset = nalu.data() - elementary_stream.data();
    const size_t size = nalu.header_size() + nalu.payload_size();
    ASSERT_GE(size, 2u);
    encrypted_[source_offsets[offset]] = Nalu::H264_FillerData;
    for (size_t i = 1; i + 1 < size; ++i)
      encrypted_[source_offsets[offset + i]] = '\xff';
    encrypted_[source_offsets[offset + size - 1]] = '\x80';
    ++replaced;
  }
  ASSERT_GT(replaced, 0u);
  ASSERT_TRUE(ParseEncrypted(&key_source_, 17));
  // Remove only the replacement filler before comparing the original samples.
  for (auto& sample : samples_) {
    BufferWriter filtered;
    NaluReader sample_reader(Nalu::kH264, 4, sample.data(), sample.size());
    while (sample_reader.Advance(&nalu) == NaluReader::kOk) {
      if (nalu.type() == Nalu::H264_FillerData)
        continue;
      const size_t size = nalu.header_size() + nalu.payload_size();
      filtered.AppendInt(static_cast<uint32_t>(size));
      filtered.AppendArray(nalu.data(), size);
    }
    filtered.SwapBuffer(&sample);
  }
  ExpectOriginalSamples();
}

TEST_F(Mp2tSampleAesTest, RejectsEncryptedAvcWithoutKeySource) {
  encrypted_.erase(0, clear_lead_size_);
  EXPECT_FALSE(ParseEncrypted(nullptr, 17));
  EXPECT_TRUE(samples_.empty());
}

TEST_F(Mp2tSampleAesTest, RejectsEncryptedAvcWithoutIv) {
  encrypted_.erase(0, clear_lead_size_);
  key_source_.key.iv.clear();
  EXPECT_FALSE(ParseEncrypted(&key_source_, 17));
  EXPECT_TRUE(samples_.empty());
}

TEST_F(Mp2tSampleAesTest, RejectsInvalidKeyAndIvSizes) {
  encrypted_.erase(0, clear_lead_size_);
  key_source_.key.iv.resize(8);
  EXPECT_FALSE(ParseEncrypted(&key_source_, 17));
  key_source_.key.iv.resize(16);
  key_source_.key.key.resize(15);
  EXPECT_FALSE(ParseEncrypted(&key_source_, 17));
  EXPECT_TRUE(samples_.empty());
}

}  // namespace mp2t
}  // namespace media
}  // namespace shaka
