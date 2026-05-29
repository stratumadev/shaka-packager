// Copyright 2014 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <packager/media/base/aes_encryptor.h>

#include <algorithm>
#include <limits>

#if defined(_M_X64) && !defined(__clang__)
#include <intrin.h>
#endif

#include <absl/log/check.h>
#include <absl/log/log.h>

#include <packager/macros/crypto.h>

namespace {

uint64_t ReadBigEndian64(const uint8_t* data) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i)
    value = (value << 8) | data[i];
  return value;
}

void AddBigEndian64(uint8_t* data, uint64_t increment) {
  for (int i = 7; i >= 0 && increment > 0; --i) {
    increment += data[i];
    data[i] = increment & 0xFF;
    increment >>= 8;
  }
}

#if defined(_M_X64) && !defined(__clang__)
void WriteBigEndian64(uint8_t* data, uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    data[i] = value & 0xFF;
    value >>= 8;
  }
}
#endif

size_t GeneratedBlockCount(size_t block_offset, size_t size) {
  if (size == 0)
    return 0;

  const size_t old_blocks = block_offset == 0 ? 0 : 1;
  return (block_offset + size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE -
         old_blocks;
}

size_t BytesUntil64BitCounterWrap(const std::vector<uint8_t>& counter,
                                  size_t block_offset) {
  DCHECK_EQ(counter.size(), static_cast<size_t>(AES_BLOCK_SIZE));
  const uint64_t low_counter = ReadBigEndian64(&counter[8]);
  if (low_counter == 0)
    return std::numeric_limits<size_t>::max();

  const uint64_t blocks_until_wrap =
      std::numeric_limits<uint64_t>::max() - low_counter + 1;

  if (blocks_until_wrap >
      std::numeric_limits<size_t>::max() / AES_BLOCK_SIZE) {
    return std::numeric_limits<size_t>::max();
  }

  const size_t encrypted_bytes_until_wrap =
      static_cast<size_t>(blocks_until_wrap) * AES_BLOCK_SIZE;
  if (block_offset == 0)
    return encrypted_bytes_until_wrap;
  return encrypted_bytes_until_wrap + (AES_BLOCK_SIZE - block_offset);
}

}  // namespace

namespace shaka {
namespace media {

#if defined(_M_X64) && !defined(__clang__)
namespace {

bool CpuHasAesNi() {
  int cpu_info[4] = {};
  __cpuid(cpu_info, 1);
  return (cpu_info[2] & (1 << 25)) != 0;
}

inline __m128i Aes128KeyAssist(__m128i key, __m128i assist) {
  assist = _mm_shuffle_epi32(assist, 0xff);
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, assist);
}

#define AES128_EXPAND_KEY(round_key, rcon) \
  Aes128KeyAssist((round_key), _mm_aeskeygenassist_si128((round_key), (rcon)))

void ExpandAes128Key(const uint8_t* key, __m128i* round_keys) {
  round_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
  round_keys[1] = AES128_EXPAND_KEY(round_keys[0], 0x01);
  round_keys[2] = AES128_EXPAND_KEY(round_keys[1], 0x02);
  round_keys[3] = AES128_EXPAND_KEY(round_keys[2], 0x04);
  round_keys[4] = AES128_EXPAND_KEY(round_keys[3], 0x08);
  round_keys[5] = AES128_EXPAND_KEY(round_keys[4], 0x10);
  round_keys[6] = AES128_EXPAND_KEY(round_keys[5], 0x20);
  round_keys[7] = AES128_EXPAND_KEY(round_keys[6], 0x40);
  round_keys[8] = AES128_EXPAND_KEY(round_keys[7], 0x80);
  round_keys[9] = AES128_EXPAND_KEY(round_keys[8], 0x1B);
  round_keys[10] = AES128_EXPAND_KEY(round_keys[9], 0x36);
}

#undef AES128_EXPAND_KEY

inline __m128i Aes128EncryptBlock(__m128i block, const __m128i* round_keys) {
  block = _mm_xor_si128(block, round_keys[0]);
  for (int round = 1; round < 10; ++round)
    block = _mm_aesenc_si128(block, round_keys[round]);
  return _mm_aesenclast_si128(block, round_keys[10]);
}

void EncryptCtrBlocks8(const uint8_t* counters,
                       const __m128i* round_keys,
                       uint8_t* key_stream) {
  __m128i blocks[8];
  for (int i = 0; i < 8; ++i) {
    blocks[i] = _mm_loadu_si128(
        reinterpret_cast<const __m128i*>(counters + i * AES_BLOCK_SIZE));
    blocks[i] = _mm_xor_si128(blocks[i], round_keys[0]);
  }
  for (int round = 1; round < 10; ++round) {
    for (int i = 0; i < 8; ++i)
      blocks[i] = _mm_aesenc_si128(blocks[i], round_keys[round]);
  }
  for (int i = 0; i < 8; ++i) {
    blocks[i] = _mm_aesenclast_si128(blocks[i], round_keys[10]);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(key_stream + i * AES_BLOCK_SIZE),
                     blocks[i]);
  }
}

}  // namespace
#endif  // defined(_M_X64) && !defined(__clang__)

// We don't support constant iv for counter mode, as we don't have a use case
// for that.
AesCtrEncryptor::AesCtrEncryptor()
    : AesCryptor(kDontUseConstantIv), block_offset_(0) {}

AesCtrEncryptor::~AesCtrEncryptor() {}

bool AesCtrEncryptor::InitializeWithIv(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& iv) {
#if defined(_M_X64) && !defined(__clang__)
  use_aesni_128_ = key.size() == 16 && CpuHasAesNi();
  if (use_aesni_128_)
    ExpandAes128Key(key.data(), aesni_round_keys_);
#endif

  if (!SetupCipher(key.size(), kCtrMode)) {
    return false;
  }

  if (mbedtls_cipher_setkey(&cipher_ctx_, key.data(),
                            static_cast<int>(8 * key.size()),
                            MBEDTLS_ENCRYPT) != 0) {
    LOG(ERROR) << "Failed to set CTR encryption key";
    return false;
  }

  return SetIv(iv);
}

bool AesCtrEncryptor::CryptInternal(const uint8_t* plaintext,
                                    size_t plaintext_size,
                                    uint8_t* ciphertext,
                                    size_t* ciphertext_size) {
  DCHECK(plaintext);
  DCHECK(ciphertext);

  // |ciphertext_size| is always the same as |plaintext_size| for counter mode.
  if (*ciphertext_size < plaintext_size) {
    LOG(ERROR) << "Expecting output size of at least " << plaintext_size
               << " bytes.";
    return false;
  }
  *ciphertext_size = plaintext_size;

#if defined(_M_X64) && !defined(__clang__)
  if (use_aesni_128_) {
    size_t remaining_size = plaintext_size;
    const uint8_t* current_plaintext = plaintext;
    uint8_t* current_ciphertext = ciphertext;
    alignas(16) uint8_t counter_blocks[8 * AES_BLOCK_SIZE];
    alignas(16) uint8_t key_stream[8 * AES_BLOCK_SIZE];

    while (remaining_size > 0) {
      if (block_offset_ != 0) {
        const __m128i counter_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(counter_.data()));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(key_stream),
                         Aes128EncryptBlock(counter_block, aesni_round_keys_));
        const size_t crypt_size =
            std::min(remaining_size,
                     static_cast<size_t>(AES_BLOCK_SIZE - block_offset_));
        for (size_t i = 0; i < crypt_size; ++i) {
          current_ciphertext[i] =
              current_plaintext[i] ^ key_stream[block_offset_ + i];
        }
        block_offset_ += crypt_size;
        if (block_offset_ == AES_BLOCK_SIZE) {
          block_offset_ = 0;
          AddBigEndian64(&counter_[8], 1);
        }
        current_plaintext += crypt_size;
        current_ciphertext += crypt_size;
        remaining_size -= crypt_size;
        continue;
      }

      while (remaining_size >= 8 * AES_BLOCK_SIZE) {
        const uint64_t low_counter = ReadBigEndian64(&counter_[8]);
        if (std::numeric_limits<uint64_t>::max() - low_counter < 7)
          break;
        for (int i = 0; i < 8; ++i) {
          memcpy(counter_blocks + i * AES_BLOCK_SIZE, counter_.data(),
                 AES_BLOCK_SIZE);
          WriteBigEndian64(counter_blocks + i * AES_BLOCK_SIZE + 8,
                           low_counter + i);
        }
        EncryptCtrBlocks8(counter_blocks, aesni_round_keys_, key_stream);
        for (size_t i = 0; i < 8 * AES_BLOCK_SIZE; ++i)
          current_ciphertext[i] = current_plaintext[i] ^ key_stream[i];

        AddBigEndian64(&counter_[8], 8);
        current_plaintext += 8 * AES_BLOCK_SIZE;
        current_ciphertext += 8 * AES_BLOCK_SIZE;
        remaining_size -= 8 * AES_BLOCK_SIZE;
      }

      while (remaining_size >= AES_BLOCK_SIZE) {
        const __m128i counter_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(counter_.data()));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(key_stream),
                         Aes128EncryptBlock(counter_block, aesni_round_keys_));
        for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
          current_ciphertext[i] = current_plaintext[i] ^ key_stream[i];
        AddBigEndian64(&counter_[8], 1);
        current_plaintext += AES_BLOCK_SIZE;
        current_ciphertext += AES_BLOCK_SIZE;
        remaining_size -= AES_BLOCK_SIZE;
      }

      if (remaining_size > 0) {
        const __m128i counter_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(counter_.data()));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(key_stream),
                         Aes128EncryptBlock(counter_block, aesni_round_keys_));
        for (size_t i = 0; i < remaining_size; ++i)
          current_ciphertext[i] = current_plaintext[i] ^ key_stream[i];
        block_offset_ = remaining_size;
        remaining_size = 0;
      }
    }
    return true;
  }
#endif

  size_t remaining_size = plaintext_size;
  const uint8_t* current_plaintext = plaintext;
  uint8_t* current_ciphertext = ciphertext;

  while (remaining_size > 0) {
    const size_t block_offset = block_offset_;
    const size_t max_chunk_size =
        BytesUntil64BitCounterWrap(counter_, block_offset);
    const size_t chunk_size = std::min(remaining_size, max_chunk_size);

    size_t output_size = 0;
    const int rv =
        mbedtls_cipher_update(&cipher_ctx_, current_plaintext, chunk_size,
                              current_ciphertext, &output_size);
    if (rv != 0) {
      LOG(ERROR) << "CTR encryption failed: " << rv;
      return false;
    }
    DCHECK_EQ(output_size, chunk_size);

    AddBigEndian64(&counter_[8], GeneratedBlockCount(block_offset, chunk_size));
    block_offset_ = (block_offset_ + chunk_size) % AES_BLOCK_SIZE;

    current_plaintext += chunk_size;
    current_ciphertext += chunk_size;
    remaining_size -= chunk_size;

    if (remaining_size > 0) {
      DCHECK_EQ(block_offset_, 0u);
      CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx_, counter_.data(),
                                     counter_.size()),
               0);
      CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx_), 0);
    }
  }
  return true;
}

void AesCtrEncryptor::SetIvInternal() {
  block_offset_ = 0;
  counter_ = iv();
  counter_.resize(AES_BLOCK_SIZE, 0);
  CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx_, counter_.data(),
                                 counter_.size()),
           0);
  CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx_), 0);
}

AesCbcEncryptor::AesCbcEncryptor(CbcPaddingScheme padding_scheme)
    : AesCbcEncryptor(padding_scheme, kDontUseConstantIv) {}

AesCbcEncryptor::AesCbcEncryptor(CbcPaddingScheme padding_scheme,
                                 ConstantIvFlag constant_iv_flag)
    : AesCryptor(constant_iv_flag), padding_scheme_(padding_scheme) {
  if (padding_scheme_ != kNoPadding) {
    CHECK_EQ(constant_iv_flag, kUseConstantIv)
        << "non-constant iv (cipher block chain across calls) only makes sense "
           "if the padding_scheme is kNoPadding.";
  }
}

AesCbcEncryptor::~AesCbcEncryptor() {}

bool AesCbcEncryptor::InitializeWithIv(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& iv) {
  if (!SetupCipher(key.size(), kCbcMode)) {
    return false;
  }

  if (mbedtls_cipher_setkey(&cipher_ctx_, key.data(),
                            static_cast<int>(8 * key.size()),
                            MBEDTLS_ENCRYPT) != 0) {
    LOG(ERROR) << "Failed to set CBC encryption key";
    return false;
  }

  return SetIv(iv);
}

size_t AesCbcEncryptor::RequiredOutputSize(size_t plaintext_size) {
  return plaintext_size + NumPaddingBytes(plaintext_size);
}

bool AesCbcEncryptor::CryptInternal(const uint8_t* plaintext,
                                    size_t plaintext_size,
                                    uint8_t* ciphertext,
                                    size_t* ciphertext_size) {
  const size_t residual_block_size = plaintext_size % AES_BLOCK_SIZE;
  const size_t num_padding_bytes = NumPaddingBytes(plaintext_size);
  const size_t required_ciphertext_size = RequiredOutputSize(plaintext_size);

  if (*ciphertext_size < required_ciphertext_size) {
    LOG(ERROR) << "Expecting output size of at least "
               << required_ciphertext_size << " bytes.";
    return false;
  }
  *ciphertext_size = required_ciphertext_size;

  // Encrypt everything but the residual block using CBC.
  const size_t cbc_size = plaintext_size - residual_block_size;
  if (cbc_size != 0) {
    CbcEncryptBlocks(plaintext, cbc_size, ciphertext, internal_iv_.data());
  } else if (padding_scheme_ == kCtsPadding) {
    // Don't have a full block, leave unencrypted.
    memcpy(ciphertext, plaintext, plaintext_size);
    return true;
  }
  if (residual_block_size == 0 && padding_scheme_ != kPkcs5Padding) {
    // No residual block. No need to do padding.
    return true;
  }

  if (padding_scheme_ == kNoPadding) {
    // The residual block is left unencrypted.
    memcpy(ciphertext + cbc_size, plaintext + cbc_size, residual_block_size);
    return true;
  }

  std::vector<uint8_t> residual_block(plaintext + cbc_size,
                                      plaintext + plaintext_size);
  DCHECK_EQ(residual_block.size(), residual_block_size);
  uint8_t* residual_ciphertext_block = ciphertext + cbc_size;

  if (padding_scheme_ == kPkcs5Padding) {
    DCHECK_EQ(num_padding_bytes, AES_BLOCK_SIZE - residual_block_size);

    // Pad residue block with PKCS5 padding.
    residual_block.resize(AES_BLOCK_SIZE, static_cast<char>(num_padding_bytes));
    CbcEncryptBlocks(residual_block.data(), AES_BLOCK_SIZE,
                     residual_ciphertext_block, internal_iv_.data());
  } else {
    DCHECK_EQ(num_padding_bytes, 0u);
    DCHECK_EQ(padding_scheme_, kCtsPadding);

    // Zero-pad the residual block and encrypt using CBC.
    residual_block.resize(AES_BLOCK_SIZE, 0);
    CbcEncryptBlocks(residual_block.data(), AES_BLOCK_SIZE,
                     residual_block.data(), internal_iv_.data());

    // Replace the last full block with the zero-padded, encrypted residual
    // block, and replace the residual block with the equivalent portion of the
    // last full encrypted block. It may appear that some encrypted bits of the
    // last full block are lost, but they are not, as they were used as the IV
    // when encrypting the zero-padded residual block.
    // This ordering of the output is described as "CS2" in literature.
    // https://en.wikipedia.org/wiki/Ciphertext_stealing#CS2
    memcpy(residual_ciphertext_block,
           residual_ciphertext_block - AES_BLOCK_SIZE, residual_block_size);
    memcpy(residual_ciphertext_block - AES_BLOCK_SIZE, residual_block.data(),
           AES_BLOCK_SIZE);
  }
  return true;
}

void AesCbcEncryptor::SetIvInternal() {
  internal_iv_ = iv();
  internal_iv_.resize(AES_BLOCK_SIZE, 0);
}

size_t AesCbcEncryptor::NumPaddingBytes(size_t size) const {
  return (padding_scheme_ == kPkcs5Padding)
             ? (AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE))
             : 0;
}

void AesCbcEncryptor::CbcEncryptBlocks(const uint8_t* plaintext,
                                       size_t plaintext_size,
                                       uint8_t* ciphertext,
                                       uint8_t* iv) {
  CHECK_EQ(plaintext_size % AES_BLOCK_SIZE, 0u);

  size_t output_size = 0;
  CHECK_EQ(mbedtls_cipher_crypt(&cipher_ctx_, iv, AES_BLOCK_SIZE, plaintext,
                                plaintext_size, ciphertext, &output_size),
           0);

  CHECK_EQ(output_size % AES_BLOCK_SIZE, 0u);
  CHECK_GT(output_size, 0u);

  uint8_t* last_block = ciphertext + output_size - AES_BLOCK_SIZE;
  memcpy(iv, last_block, AES_BLOCK_SIZE);
}

}  // namespace media
}  // namespace shaka
