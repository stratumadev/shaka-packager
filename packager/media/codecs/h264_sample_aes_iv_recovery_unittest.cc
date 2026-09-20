// Copyright 2026 Google LLC. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <packager/media/codecs/h264_sample_aes_iv_recovery.h>

#include <array>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <packager/media/base/aes_encryptor.h>
#include <packager/media/base/aes_pattern_cryptor.h>
#include <packager/media/base/buffer_writer.h>
#include <packager/media/codecs/nal_unit_to_byte_stream_converter.h>
#include <packager/media/codecs/nalu_reader.h>
#include <packager/media/test/test_data_util.h>

namespace shaka {
namespace media {
namespace {

const std::vector<uint8_t> kKey = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};
const std::vector<uint8_t> kIv = {
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
};
const std::vector<uint8_t> kOtherKey = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
};
const std::vector<uint8_t> kOtherIv = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

const char* const kFixtures[] = {
    "h264-sample-aes-recovery-1920x256-qp13.h264",
    "h264-sample-aes-recovery-1920x320-qp13.h264",
};
const char* const kSearchLimitedFixtures[] = {
    "h264-sample-aes-recovery-1920x320-qp27.h264",
    "h264-sample-aes-recovery-1920x384-qp35.h264",
};

const uint8_t kOversizedSps[] = {
    0x67, 0x4d, 0x40, 0x1f, 0xdc, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x21, 0xa1, 0x00, 0x00, 0x03, 0x00, 0x01,
    0x00, 0x00, 0x03, 0x00, 0x0a, 0x0f, 0x18, 0x33, 0x80,
};

bool ReadFixture(const std::string& name,
                 std::vector<std::vector<uint8_t>>* nalus) {
  const std::vector<uint8_t> data = ReadTestDataFile(name);
  if (data.empty())
    return false;

  NaluReader reader(Nalu::kH264, kIsAnnexbByteStream, data.data(), data.size());
  Nalu nalu;
  while (reader.Advance(&nalu) == NaluReader::kOk) {
    const size_t size = nalu.header_size() + nalu.payload_size();
    nalus->emplace_back(nalu.data(), nalu.data() + size);
  }
  return nalus->size() == 5 && (*nalus)[0][0] == 0x67 && (*nalus)[1][0] == 0x68;
}

bool EncryptSampleAesNalu(const std::vector<uint8_t>& key,
                          const std::vector<uint8_t>& iv,
                          const std::vector<uint8_t>& clear,
                          std::vector<uint8_t>* encrypted) {
  if (clear.size() <= 48)
    return false;

  *encrypted = clear;
  AesPatternCryptor cryptor(1, 9,
                            AesPatternCryptor::kSkipIfCryptByteBlockRemaining,
                            AesCryptor::kUseConstantIv,
                            std::make_unique<AesCbcEncryptor>(kNoPadding));
  if (!cryptor.InitializeWithIv(key, iv) ||
      !cryptor.Crypt(encrypted->data() + 32, encrypted->size() - 32,
                     encrypted->data() + 32)) {
    return false;
  }

  // SAMPLE-AES adds this outer escaping after encrypting the original EBSP.
  BufferWriter escaped;
  EscapeNalByteSequence(encrypted->data(), encrypted->size(), &escaped);
  encrypted->assign(escaped.Buffer(), escaped.Buffer() + escaped.Size());
  return true;
}

std::vector<uint8_t> RemoveOuterEscaping(
    const std::vector<uint8_t>& encrypted) {
  std::vector<uint8_t> result;
  size_t zeros = 0;
  for (size_t i = 0; i < encrypted.size(); ++i) {
    if (zeros == 2 && encrypted[i] == 3 &&
        (i + 1 == encrypted.size() || encrypted[i + 1] <= 3)) {
      zeros = 0;
      continue;
    }
    result.push_back(encrypted[i]);
    zeros = encrypted[i] == 0 ? zeros + 1 : 0;
  }
  return result;
}

bool Process(H264SampleAesIvRecovery* recovery,
             const std::vector<uint8_t>& bytes) {
  Nalu nalu;
  return nalu.Initialize(Nalu::kH264, bytes.data(), bytes.size()) &&
         recovery->ProcessNalu(nalu);
}

std::vector<uint8_t> Prefix(const std::vector<uint8_t>& bytes, size_t offset) {
  return std::vector<uint8_t>(bytes.begin() + offset,
                              bytes.begin() + offset + 16);
}

class H264SampleAesIvRecoveryTest : public testing::TestWithParam<const char*> {
};

TEST_P(H264SampleAesIvRecoveryTest,
       RecoversPublicIvOnlyAfterIndependentCiphertextWitnesses) {
  std::vector<std::vector<uint8_t>> clear;
  ASSERT_TRUE(ReadFixture(GetParam(), &clear));
  ASSERT_EQ(5u, clear.size());

  H264SampleAesIvRecovery recovery(kKey);
  ASSERT_TRUE(Process(&recovery, clear[0]));
  ASSERT_TRUE(Process(&recovery, clear[1]));
  EXPECT_TRUE(recovery.iv().empty());

  std::array<std::vector<uint8_t>, 3> encrypted_slices;
  for (size_t i = 0; i < encrypted_slices.size(); ++i) {
    ASSERT_TRUE(
        EncryptSampleAesNalu(kKey, kIv, clear[i + 2], &encrypted_slices[i]));
    const std::vector<uint8_t> unescaped =
        RemoveOuterEscaping(encrypted_slices[i]);
    ASSERT_GE(unescaped.size(), 48u);
    if (i == 1) {
      EXPECT_NE(Prefix(clear[2], 0), Prefix(clear[i + 2], 0));
      EXPECT_NE(Prefix(RemoveOuterEscaping(encrypted_slices[0]), 32),
                Prefix(unescaped, 32));
    }

    ASSERT_TRUE(Process(&recovery, encrypted_slices[i]));
    if (i == 0) {
      EXPECT_TRUE(recovery.iv().empty());
    }
  }
  EXPECT_EQ(kIv, recovery.iv());
}

TEST_P(H264SampleAesIvRecoveryTest, DoesNotConfirmAValueFromOneWitness) {
  std::vector<std::vector<uint8_t>> clear;
  ASSERT_TRUE(ReadFixture(GetParam(), &clear));

  H264SampleAesIvRecovery recovery(kKey);
  ASSERT_TRUE(Process(&recovery, clear[0]));
  ASSERT_TRUE(Process(&recovery, clear[1]));
  std::vector<uint8_t> encrypted;
  ASSERT_TRUE(EncryptSampleAesNalu(kKey, kIv, clear[2], &encrypted));
  for (int i = 0; i < 3; ++i) {
    ASSERT_TRUE(Process(&recovery, encrypted));
    EXPECT_TRUE(recovery.iv().empty());
  }
}

TEST(H264SampleAesIvRecoveryTest, DoesNotConfirmAmbiguousRepeatedSyntax) {
  std::vector<std::vector<uint8_t>> clear;
  ASSERT_TRUE(ReadFixture(
      "h264-sample-aes-recovery-ambiguous-1920x256-qp13.h264", &clear));

  H264SampleAesIvRecovery recovery(kKey);
  ASSERT_TRUE(Process(&recovery, clear[0]));
  ASSERT_TRUE(Process(&recovery, clear[1]));
  for (size_t i = 0; i < 2; ++i) {
    std::vector<uint8_t> encrypted;
    ASSERT_TRUE(EncryptSampleAesNalu(kKey, kIv, clear[i + 2], &encrypted));
    ASSERT_TRUE(Process(&recovery, encrypted));
  }
  // These two periodic DC witnesses admit more than one CABAC continuation.
  // A shared candidate must not be accepted until the complete candidate-set
  // intersection is unique.
  EXPECT_TRUE(recovery.iv().empty());
}

TEST(H264SampleAesIvRecoveryTest, DoesNotConfirmWhenCandidateSearchIsCapped) {
  for (const char* fixture : kSearchLimitedFixtures) {
    SCOPED_TRACE(fixture);
    std::vector<std::vector<uint8_t>> clear;
    ASSERT_TRUE(ReadFixture(fixture, &clear));

    H264SampleAesIvRecovery recovery(kKey);
    ASSERT_TRUE(Process(&recovery, clear[0]));
    ASSERT_TRUE(Process(&recovery, clear[1]));
    for (size_t i = 0; i < 3; ++i) {
      std::vector<uint8_t> encrypted;
      ASSERT_TRUE(EncryptSampleAesNalu(kKey, kIv, clear[i + 2], &encrypted));
      ASSERT_TRUE(Process(&recovery, encrypted));
    }
    EXPECT_TRUE(recovery.iv().empty());
  }
}

TEST_P(H264SampleAesIvRecoveryTest,
       DoesNotCombineWitnessesWithDifferentKeysOrIvs) {
  std::vector<std::vector<uint8_t>> clear;
  ASSERT_TRUE(ReadFixture(GetParam(), &clear));

  H264SampleAesIvRecovery recovery(kKey);
  ASSERT_TRUE(Process(&recovery, clear[0]));
  ASSERT_TRUE(Process(&recovery, clear[1]));
  const std::array<
      std::pair<const std::vector<uint8_t>*, const std::vector<uint8_t>*>, 3>
      protection = {{{&kKey, &kIv}, {&kKey, &kOtherIv}, {&kOtherKey, &kIv}}};
  for (size_t i = 0; i < protection.size(); ++i) {
    std::vector<uint8_t> encrypted;
    ASSERT_TRUE(EncryptSampleAesNalu(
        *protection[i].first, *protection[i].second, clear[i + 2], &encrypted));
    ASSERT_TRUE(Process(&recovery, encrypted));
    EXPECT_TRUE(recovery.iv().empty());
  }
}

TEST_P(H264SampleAesIvRecoveryTest, ResetDropsUnconfirmedAndConfirmedState) {
  std::vector<std::vector<uint8_t>> clear;
  ASSERT_TRUE(ReadFixture(GetParam(), &clear));

  H264SampleAesIvRecovery recovery(kKey);
  ASSERT_TRUE(Process(&recovery, clear[0]));
  ASSERT_TRUE(Process(&recovery, clear[1]));
  for (size_t i = 0; i < 3; ++i) {
    std::vector<uint8_t> encrypted;
    ASSERT_TRUE(EncryptSampleAesNalu(kKey, kIv, clear[i + 2], &encrypted));
    ASSERT_TRUE(Process(&recovery, encrypted));
  }
  ASSERT_EQ(kIv, recovery.iv());
  recovery.Reset();
  EXPECT_TRUE(recovery.iv().empty());

  ASSERT_TRUE(Process(&recovery, clear[0]));
  ASSERT_TRUE(Process(&recovery, clear[1]));
  std::vector<uint8_t> encrypted;
  ASSERT_TRUE(EncryptSampleAesNalu(kKey, kIv, clear[4], &encrypted));
  ASSERT_TRUE(Process(&recovery, encrypted));
  EXPECT_TRUE(recovery.iv().empty());
}

TEST(H264SampleAesIvRecoveryBoundsTest, RejectsSpsWithUnrepresentableWidth) {
  // This is a public synthetic Main-profile SPS with
  // pic_width_in_mbs_minus1 == INT_MAX. It must fail before geometry is used
  // in row arithmetic.
  Nalu nalu;
  ASSERT_TRUE(
      nalu.Initialize(Nalu::kH264, kOversizedSps, std::size(kOversizedSps)));
  H264SampleAesIvRecovery recovery(kKey);
  EXPECT_FALSE(recovery.ProcessNalu(nalu));
}

INSTANTIATE_TEST_SUITE_P(PublicSyntheticFixtures,
                         H264SampleAesIvRecoveryTest,
                         testing::ValuesIn(kFixtures));

}  // namespace
}  // namespace media
}  // namespace shaka
