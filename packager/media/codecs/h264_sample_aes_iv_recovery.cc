// Copyright 2026 Google LLC. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <packager/media/codecs/h264_sample_aes_iv_recovery.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <set>
#include <tuple>
#include <utility>

#include <packager/media/base/aes_decryptor.h>
#include <packager/media/codecs/h264_parser.h>

namespace shaka {
namespace media {
namespace {

constexpr size_t kClearLead = 32;
constexpr size_t kKnownSuffixEnd = 64;
constexpr size_t kMaxSearchStates = 1000000;
constexpr size_t kMaxTotalSearchStates = 4000000;
constexpr size_t kMaxCandidates = 128;
constexpr size_t kMaxTemplates = 8;

using Iv = std::array<uint8_t, 16>;
using Coefficients = std::array<int, 16>;
using Bin = std::pair<int, int>;
constexpr int kBypass = -1;
constexpr int kTerminate = -2;

// Normative CABAC constants from ITU-T H.264, section 9.3.
constexpr int8_t kIntraContext[400][2] = {
    {20, -15},  {2, 54},    {3, 74},    {20, -15},  {2, 54},    {3, 74},
    {-28, 127}, {-23, 104}, {-6, 53},   {-1, 54},   {7, 51},    {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},     {0, 0},
    {0, 41},    {0, 63},    {0, 63},    {0, 63},    {-9, 83},   {4, 86},
    {0, 97},    {-7, 72},   {13, 41},   {3, 62},    {0, 11},    {1, 55},
    {0, 69},    {-17, 127}, {-13, 102}, {0, 82},    {-7, 74},   {-21, 107},
    {-27, 127}, {-31, 127}, {-24, 127}, {-18, 95},  {-27, 127}, {-21, 114},
    {-30, 127}, {-17, 123}, {-12, 115}, {-16, 122}, {-11, 115}, {-12, 63},
    {-2, 68},   {-15, 84},  {-13, 104}, {-3, 70},   {-8, 93},   {-10, 90},
    {-30, 127}, {-1, 74},   {-6, 97},   {-7, 91},   {-20, 127}, {-4, 56},
    {-5, 82},   {-7, 76},   {-22, 125}, {-7, 93},   {-11, 87},  {-3, 77},
    {-5, 71},   {-4, 63},   {-4, 68},   {-12, 84},  {-7, 62},   {-7, 65},
    {8, 61},    {5, 56},    {-2, 66},   {1, 64},    {0, 61},    {-2, 78},
    {1, 50},    {7, 52},    {10, 35},   {0, 44},    {11, 38},   {1, 45},
    {0, 46},    {5, 44},    {31, 17},   {1, 51},    {7, 50},    {28, 19},
    {16, 33},   {14, 62},   {-13, 108}, {-15, 100}, {-13, 101}, {-13, 91},
    {-12, 94},  {-10, 88},  {-16, 84},  {-10, 86},  {-7, 83},   {-13, 87},
    {-19, 94},  {1, 70},    {0, 72},    {-5, 74},   {18, 59},   {-8, 102},
    {-15, 100}, {0, 95},    {-4, 75},   {2, 72},    {-11, 75},  {-3, 71},
    {15, 46},   {-13, 69},  {0, 62},    {0, 65},    {21, 37},   {-15, 72},
    {9, 57},    {16, 54},   {0, 62},    {12, 72},   {24, 0},    {15, 9},
    {8, 25},    {13, 18},   {15, 9},    {13, 19},   {10, 37},   {12, 18},
    {6, 29},    {20, 33},   {15, 30},   {4, 45},    {1, 58},    {0, 62},
    {7, 61},    {12, 38},   {11, 45},   {15, 39},   {11, 42},   {13, 44},
    {16, 45},   {12, 41},   {10, 49},   {30, 34},   {18, 42},   {10, 55},
    {17, 51},   {17, 46},   {0, 89},    {26, -19},  {22, -17},  {26, -17},
    {30, -25},  {28, -20},  {33, -23},  {37, -27},  {33, -23},  {40, -28},
    {38, -17},  {33, -11},  {40, -15},  {41, -6},   {38, 1},    {41, 17},
    {30, -6},   {27, 3},    {26, 22},   {37, -16},  {35, -4},   {38, -8},
    {38, -3},   {37, 3},    {38, 5},    {42, 0},    {35, 16},   {39, 22},
    {14, 48},   {27, 37},   {21, 60},   {12, 68},   {2, 97},    {-3, 71},
    {-6, 42},   {-5, 50},   {-3, 54},   {-2, 62},   {0, 58},    {1, 63},
    {-2, 72},   {-1, 74},   {-9, 91},   {-5, 67},   {-5, 27},   {-3, 39},
    {-2, 44},   {0, 46},    {-16, 64},  {-8, 68},   {-10, 78},  {-6, 77},
    {-10, 86},  {-12, 92},  {-15, 55},  {-10, 60},  {-6, 62},   {-4, 65},
    {-12, 73},  {-8, 76},   {-7, 80},   {-9, 88},   {-17, 110}, {-11, 97},
    {-20, 84},  {-11, 79},  {-6, 73},   {-4, 74},   {-13, 86},  {-13, 96},
    {-11, 97},  {-19, 117}, {-8, 78},   {-5, 33},   {-4, 48},   {-2, 53},
    {-3, 62},   {-13, 71},  {-10, 79},  {-12, 86},  {-13, 90},  {-14, 97},
    {0, 0},     {-6, 93},   {-6, 84},   {-8, 79},   {0, 66},    {-1, 71},
    {0, 62},    {-2, 60},   {-2, 59},   {-5, 75},   {-3, 62},   {-4, 58},
    {-9, 66},   {-1, 79},   {0, 71},    {3, 68},    {10, 44},   {-7, 62},
    {15, 36},   {14, 40},   {16, 27},   {12, 29},   {1, 44},    {20, 36},
    {18, 32},   {5, 42},    {1, 48},    {10, 62},   {17, 46},   {9, 64},
    {-12, 104}, {-11, 97},  {-16, 96},  {-7, 88},   {-8, 85},   {-7, 85},
    {-9, 85},   {-13, 88},  {4, 66},    {-3, 77},   {-3, 76},   {-6, 76},
    {10, 58},   {-1, 76},   {-1, 83},   {-7, 99},   {-14, 95},  {2, 95},
    {0, 76},    {-5, 74},   {0, 70},    {-11, 75},  {1, 68},    {0, 65},
    {-14, 73},  {3, 62},    {4, 62},    {-1, 68},   {-13, 75},  {11, 55},
    {5, 64},    {12, 70},   {15, 6},    {6, 19},    {7, 16},    {12, 14},
    {18, 13},   {13, 11},   {13, 15},   {15, 16},   {12, 23},   {13, 23},
    {15, 20},   {14, 26},   {14, 44},   {17, 40},   {17, 47},   {24, 17},
    {21, 21},   {25, 22},   {31, 27},   {22, 29},   {19, 35},   {14, 50},
    {10, 57},   {7, 63},    {-2, 77},   {-4, 82},   {-3, 94},   {9, 69},
    {-12, 109}, {36, -35},  {36, -34},  {32, -26},  {37, -30},  {44, -32},
    {34, -18},  {34, -15},  {40, -15},  {33, -7},   {35, -5},   {33, 0},
    {38, 2},    {33, 13},   {23, 35},   {13, 58},   {29, -3},   {26, 0},
    {22, 30},   {31, -7},   {35, -15},  {34, -3},   {34, 3},    {36, -1},
    {34, 5},    {32, 11},   {35, 5},    {34, 12},   {39, 11},   {30, 29},
    {34, 26},   {29, 39},   {19, 66},   {31, 21},
};
constexpr uint8_t kRangeLps[64][4] = {
    {128, 176, 208, 240}, {128, 167, 197, 227}, {128, 158, 187, 216},
    {123, 150, 178, 205}, {116, 142, 169, 195}, {111, 135, 160, 185},
    {105, 128, 152, 175}, {100, 122, 144, 166}, {95, 116, 137, 158},
    {90, 110, 130, 150},  {85, 104, 123, 142},  {81, 99, 117, 135},
    {77, 94, 111, 128},   {73, 89, 105, 122},   {69, 85, 100, 116},
    {66, 80, 95, 110},    {62, 76, 90, 104},    {59, 72, 86, 99},
    {56, 69, 81, 94},     {53, 65, 77, 89},     {51, 62, 73, 85},
    {48, 59, 69, 80},     {46, 56, 66, 76},     {43, 53, 63, 72},
    {41, 50, 59, 69},     {39, 48, 56, 65},     {37, 45, 54, 62},
    {35, 43, 51, 59},     {33, 41, 48, 56},     {32, 39, 46, 53},
    {30, 37, 43, 50},     {29, 35, 41, 48},     {27, 33, 39, 45},
    {26, 31, 37, 43},     {24, 30, 35, 41},     {23, 28, 33, 39},
    {22, 27, 32, 37},     {21, 26, 30, 35},     {20, 24, 29, 33},
    {19, 23, 27, 31},     {18, 22, 26, 30},     {17, 21, 25, 28},
    {16, 20, 23, 27},     {15, 19, 22, 25},     {14, 18, 21, 24},
    {14, 17, 20, 23},     {13, 16, 19, 22},     {12, 15, 18, 21},
    {12, 14, 17, 20},     {11, 14, 16, 19},     {11, 13, 15, 18},
    {10, 12, 15, 17},     {10, 12, 14, 16},     {9, 11, 13, 15},
    {9, 11, 12, 14},      {8, 10, 12, 14},      {8, 9, 11, 13},
    {7, 9, 11, 12},       {7, 9, 10, 12},       {7, 8, 10, 11},
    {6, 8, 9, 11},        {6, 7, 9, 10},        {6, 7, 8, 9},
    {2, 2, 2, 2},
};
constexpr uint8_t kNextMps[64] = {
    1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 62, 63};
constexpr uint8_t kNextLps[64] = {
    0,  0,  1,  2,  2,  4,  4,  5,  6,  7,  8,  9,  9,  11, 11, 12,
    13, 13, 15, 15, 16, 16, 18, 18, 19, 19, 21, 21, 22, 22, 23, 24,
    24, 25, 26, 26, 27, 27, 28, 29, 29, 30, 30, 30, 31, 32, 32, 33,
    33, 33, 34, 34, 35, 35, 35, 36, 36, 36, 37, 37, 37, 38, 38, 63};

struct CabacState {
  std::array<uint8_t, 400> contexts{};
  unsigned range = 510;

  explicit CabacState(int qp) {
    for (size_t i = 0; i < contexts.size(); ++i) {
      const int pre =
          std::max(1, std::min(126, ((kIntraContext[i][0] * qp) >> 4) +
                                        kIntraContext[i][1]));
      contexts[i] = pre <= 63 ? (63 - pre) * 2 : (pre - 64) * 2 + 1;
    }
  }

  void Update(int context, int bin) {
    uint8_t& state = contexts[context];
    const unsigned probability = state >> 1;
    int mps = state & 1;
    if (bin == mps) {
      state = (kNextMps[probability] << 1) | mps;
    } else {
      if (probability == 0)
        mps ^= 1;
      state = (kNextLps[probability] << 1) | mps;
    }
  }
};

// This reader never reads beyond the known prefix, including arithmetic
// lookahead. An incomplete macroblock is discarded together with its bins.
class CabacReader : public CabacState {
 public:
  CabacReader(const std::vector<uint8_t>& data, int qp)
      : CabacState(qp), data_(data) {
    for (int i = 0; i < 9; ++i)
      offset_ = offset_ * 2 + ReadBit();
  }

  int Read(int context) {
    const unsigned state = contexts[context];
    const unsigned lps = kRangeLps[state >> 1][(range >> 6) - 4];
    range -= lps;
    int bin = state & 1;
    if (offset_ >= range) {
      bin ^= 1;
      offset_ -= range;
      range = lps;
    }
    Update(context, bin);
    bins.emplace_back(context, bin);
    Normalize();
    return bin;
  }

  int Bypass() {
    offset_ = offset_ * 2 + ReadBit();
    const int bin = offset_ >= range;
    if (bin)
      offset_ -= range;
    bins.emplace_back(kBypass, bin);
    return bin;
  }

  int Terminate() {
    range -= 2;
    const int bin = offset_ >= range;
    bins.emplace_back(kTerminate, bin);
    if (!bin)
      Normalize();
    return bin;
  }

  bool valid = true;
  std::vector<Bin> bins;

 private:
  unsigned ReadBit() {
    if (position_ == data_.size() * 8) {
      valid = false;
      return 0;
    }
    const unsigned bit = (data_[position_ / 8] >> (7 - position_ % 8)) & 1;
    ++position_;
    return bit;
  }

  void Normalize() {
    while (range < 256) {
      range *= 2;
      offset_ = offset_ * 2 + ReadBit();
    }
  }

  const std::vector<uint8_t>& data_;
  size_t position_ = 0;
  unsigned offset_ = 0;
};

// Bitwise arithmetic encoding (H.264 section 9.3). Only completed output bytes
// are compared; pending bits must never be treated as known plaintext.
class CabacWriter : public CabacState {
 public:
  CabacWriter(const std::vector<uint8_t>& header, int qp)
      : CabacState(qp), size_(header.size()) {
    valid = size_ <= bytes.size();
    if (valid)
      std::copy(header.begin(), header.end(), bytes.begin());
  }

  void Write(int context, int bin) {
    if (!valid)
      return;
    if (context == kBypass) {
      low_ = low_ * 2 + bin * range;
      if (low_ >= 1024) {
        Resolve(1);
        low_ -= 1024;
      } else if (low_ < 512) {
        Resolve(0);
      } else {
        ++pending_;
        low_ -= 512;
      }
      return;
    }
    if (context == kTerminate) {
      if (bin) {
        valid = false;
        return;
      }
      range -= 2;
    } else {
      const unsigned state = contexts[context];
      const unsigned lps = kRangeLps[state >> 1][(range >> 6) - 4];
      range -= lps;
      if (bin != static_cast<int>(state & 1)) {
        low_ += range;
        range = lps;
      }
      Update(context, bin);
    }
    while (range < 256) {
      if (low_ < 256) {
        Resolve(0);
      } else if (low_ >= 512) {
        Resolve(1);
        low_ -= 512;
      } else {
        ++pending_;
        low_ -= 256;
      }
      low_ *= 2;
      range *= 2;
    }
  }

  size_t complete_bytes() const { return size_ - (used_bits_ != 0); }
  bool valid = true;
  std::array<uint8_t, 128> bytes{};

 private:
  void Emit(int bit) {
    if (skip_first_) {
      skip_first_ = false;
      return;
    }
    if (used_bits_ == 0) {
      if (size_ == bytes.size()) {
        valid = false;
        return;
      }
      bytes[size_++] = 0;
    }
    bytes[size_ - 1] |= bit << (7 - used_bits_);
    used_bits_ = (used_bits_ + 1) % 8;
  }

  void Resolve(int bit) {
    Emit(bit);
    while (pending_ && valid) {
      Emit(!bit);
      --pending_;
    }
  }

  size_t size_ = 0;
  unsigned low_ = 0;
  unsigned pending_ = 0;
  unsigned used_bits_ = 0;
  bool skip_first_ = true;
};

constexpr int kSignificant[] = {105, 120, 134, 149, 152};
constexpr int kLast[] = {166, 181, 195, 210, 213};
constexpr int kLevel[] = {227, 237, 247, 257, 266};
constexpr int kLevelOne[] = {1, 2, 3, 4, 0, 0, 0, 0};
constexpr int kLevelGreater[] = {5, 5, 5, 5, 6, 7, 8, 9};
constexpr int kAfterOne[] = {1, 2, 3, 3, 4, 5, 6, 7};
constexpr int kAfterGreater[] = {4, 4, 4, 4, 5, 6, 7, 7};

void ReadResidual(CabacReader* reader,
                  int category,
                  int count,
                  Coefficients* coefficients) {
  std::vector<int> positions;
  int index = 0;
  for (; index < count - 1; ++index) {
    if (reader->Read(kSignificant[category] + index)) {
      positions.push_back(index);
      if (reader->Read(kLast[category] + index))
        break;
    }
  }
  if (index == count - 1)
    positions.push_back(index);
  int node = 0;
  for (auto it = positions.rbegin(); it != positions.rend(); ++it) {
    int level = 1;
    if (reader->Read(kLevel[category] + kLevelOne[node])) {
      const int context = kLevel[category] + kLevelGreater[node];
      node = kAfterGreater[node];
      level = 2;
      while (level < 15 && reader->Read(context))
        ++level;
      if (level == 15) {
        int bits = 0;
        while (reader->Bypass()) {
          if (++bits > 16) {
            reader->valid = false;
            return;
          }
        }
        level = 1;
        while (bits--)
          level = level * 2 + reader->Bypass();
        level += 14;
      }
    } else {
      node = kAfterOne[node];
    }
    (*coefficients)[*it] = reader->Bypass() ? -level : level;
  }
}

bool HasCoefficients(const Coefficients& coefficients) {
  return std::any_of(coefficients.begin(), coefficients.end(),
                     [](int value) { return value != 0; });
}

void WriteResidual(CabacWriter* writer,
                   int category,
                   int count,
                   const Coefficients& coefficients) {
  int last = count - 1;
  while (last > 0 && !coefficients[last])
    --last;
  for (int i = 0; i < count - 1; ++i) {
    const bool significant = coefficients[i] != 0;
    writer->Write(kSignificant[category] + i, significant);
    if (significant) {
      writer->Write(kLast[category] + i, i == last);
      if (i == last)
        break;
    }
  }
  int node = 0;
  for (int i = last; i >= 0; --i) {
    if (!coefficients[i])
      continue;
    const int level = std::abs(coefficients[i]);
    writer->Write(kLevel[category] + kLevelOne[node], level != 1);
    if (level == 1) {
      node = kAfterOne[node];
    } else {
      const int context = kLevel[category] + kLevelGreater[node];
      node = kAfterGreater[node];
      for (int value = 2; value < std::min(level, 15); ++value)
        writer->Write(context, 1);
      if (level < 15) {
        writer->Write(context, 0);
      } else {
        const unsigned value = level - 14;
        unsigned bits = 0;
        for (unsigned n = value; n > 1; n >>= 1)
          ++bits;
        for (unsigned n = 0; n < bits; ++n)
          writer->Write(kBypass, 1);
        writer->Write(kBypass, 0);
        while (bits--)
          writer->Write(kBypass, (value >> bits) & 1);
      }
    }
    writer->Write(kBypass, coefficients[i] < 0);
  }
}

struct Macroblock {
  bool intra16 = false;
  int luma_mode = 0;
  int chroma_mode = 0;
  int luma_cbp = 0;
  int chroma_cbp = 0;
  int qp_delta = 0;
  Coefficients luma_dc{};
  std::array<Coefficients, 2> chroma_dc{};
  std::array<int, 24> nonzero{};

  bool operator<(const Macroblock& other) const {
    return std::tie(luma_mode, chroma_mode, chroma_cbp, luma_dc, chroma_dc) <
           std::tie(other.luma_mode, other.chroma_mode, other.chroma_cbp,
                    other.luma_dc, other.chroma_dc);
  }
};

bool ReadMacroblock(CabacReader* reader,
                    const Macroblock* left,
                    bool transform_8x8,
                    Macroblock* mb) {
  mb->intra16 = reader->Read(3 + (left && left->intra16));
  if (mb->intra16) {
    if (reader->Terminate())
      return false;  // I_PCM is outside this bounded recovery path.
    mb->luma_cbp = 15 * reader->Read(6);
    if (reader->Read(7))
      mb->chroma_cbp = 1 + reader->Read(8);
    mb->luma_mode = 2 * reader->Read(9);
    mb->luma_mode += reader->Read(10);
  } else {
    if (transform_8x8 && reader->Read(399))
      return false;
    for (int i = 0; i < 16; ++i) {
      if (!reader->Read(68)) {
        reader->Read(69);
        reader->Read(69);
        reader->Read(69);
      }
    }
  }
  if (reader->Read(64 + (left && left->chroma_mode != 0))) {
    mb->chroma_mode = 1;
    if (reader->Read(67))
      mb->chroma_mode = 2 + reader->Read(67);
  }
  if (!mb->intra16) {
    const int cbp_left = left ? left->luma_cbp : 15;
    int& cbp = mb->luma_cbp;
    cbp = reader->Read(73 + !(cbp_left & 2));
    cbp |= reader->Read(73 + !(cbp & 1)) << 1;
    cbp |= reader->Read(73 + !(cbp_left & 8) + 2 * !(cbp & 1)) << 2;
    cbp |= reader->Read(73 + !(cbp & 4) + 2 * !(cbp & 2)) << 3;
    const int chroma_left = left ? left->chroma_cbp : 0;
    if (reader->Read(77 + (chroma_left > 0)))
      mb->chroma_cbp = 1 + reader->Read(81 + (chroma_left == 2));
  }
  if (mb->intra16 || mb->luma_cbp || mb->chroma_cbp) {
    if (reader->Read(60 + (left && left->qp_delta != 0))) {
      int value = 1;
      while (reader->Read(value == 1 ? 62 : 63)) {
        if (++value > 102)
          return false;
      }
      mb->qp_delta = (value & 1) ? (value + 1) / 2 : -(value + 1) / 2;
    }
    if (mb->intra16 &&
        reader->Read(87 + (left ? HasCoefficients(left->luma_dc) : 1)))
      ReadResidual(reader, 0, 16, &mb->luma_dc);
    for (int i = 0; i < 16; ++i) {
      if (!(mb->luma_cbp & (1 << (i / 4))))
        continue;
      const int x = ((i / 4) % 2) * 2 + i % 2;
      const int y = (i / 8) * 2 + (i % 4) / 2;
      const int a = x      ? mb->nonzero[y * 4 + x - 1]
                    : left ? left->nonzero[y * 4 + 3]
                           : 1;
      const int b = y ? mb->nonzero[(y - 1) * 4 + x] : 1;
      if (reader->Read((mb->intra16 ? 89 : 93) + (a != 0) + 2 * (b != 0))) {
        Coefficients coefficients{};
        ReadResidual(reader, mb->intra16 ? 1 : 2, mb->intra16 ? 15 : 16,
                     &coefficients);
        mb->nonzero[y * 4 + x] =
            std::count_if(coefficients.begin(), coefficients.end(),
                          [](int n) { return n != 0; });
      }
    }
    if (mb->chroma_cbp) {
      for (int plane = 0; plane < 2; ++plane) {
        if (reader->Read(99 +
                         (left ? HasCoefficients(left->chroma_dc[plane]) : 1)))
          ReadResidual(reader, 3, 4, &mb->chroma_dc[plane]);
      }
      if (mb->chroma_cbp == 2) {
        for (int plane = 0; plane < 2; ++plane) {
          const int base = 16 + plane * 4;
          for (int i = 0; i < 4; ++i) {
            const int a = i % 2  ? mb->nonzero[base + i - 1]
                          : left ? left->nonzero[base + i + 1]
                                 : 1;
            const int b = i / 2 ? mb->nonzero[base + i - 2] : 1;
            if (reader->Read(101 + (a != 0) + 2 * (b != 0))) {
              Coefficients coefficients{};
              ReadResidual(reader, 4, 15, &coefficients);
              mb->nonzero[base + i] =
                  std::count_if(coefficients.begin(), coefficients.end(),
                                [](int n) { return n != 0; });
            }
          }
        }
      }
    }
  }
  return !reader->Terminate() && reader->valid;
}

void WriteMacroblock(CabacWriter* writer,
                     const Macroblock& left,
                     const Macroblock& mb) {
  writer->Write(3 + left.intra16, 1);
  writer->Write(kTerminate, 0);
  writer->Write(6, 0);
  writer->Write(7, mb.chroma_cbp != 0);
  if (mb.chroma_cbp)
    writer->Write(8, 0);
  writer->Write(9, mb.luma_mode >> 1);
  writer->Write(10, mb.luma_mode & 1);
  writer->Write(64 + (left.chroma_mode != 0), mb.chroma_mode != 0);
  if (mb.chroma_mode) {
    writer->Write(67, mb.chroma_mode != 1);
    if (mb.chroma_mode != 1)
      writer->Write(67, mb.chroma_mode == 3);
  }
  writer->Write(60 + (left.qp_delta != 0), 0);
  const bool luma_dc = HasCoefficients(mb.luma_dc);
  writer->Write(87 + HasCoefficients(left.luma_dc), luma_dc);
  if (luma_dc)
    WriteResidual(writer, 0, 16, mb.luma_dc);
  if (mb.chroma_cbp) {
    for (int plane = 0; plane < 2; ++plane) {
      const bool nonzero = HasCoefficients(mb.chroma_dc[plane]);
      writer->Write(99 + HasCoefficients(left.chroma_dc[plane]), nonzero);
      if (nonzero)
        WriteResidual(writer, 3, 4, mb.chroma_dc[plane]);
    }
  }
  writer->Write(kTerminate, 0);
}

std::vector<uint8_t> Unescape(const uint8_t* data,
                              size_t size,
                              size_t limit = kKnownSuffixEnd) {
  std::vector<uint8_t> output;
  unsigned zeros = 0;
  for (size_t i = 0; i < size && output.size() < limit; ++i) {
    if (zeros == 2 && data[i] == 3 && (i + 1 == size || data[i + 1] <= 3)) {
      zeros = 0;
      continue;
    }
    output.push_back(data[i]);
    zeros = data[i] == 0 ? zeros + 1 : 0;
  }
  return output;
}

void Escape(const CabacWriter& writer, std::vector<uint8_t>* output) {
  output->clear();
  unsigned zeros = 0;
  for (size_t i = 0;
       i < writer.complete_bytes() && output->size() < kKnownSuffixEnd; ++i) {
    const uint8_t byte = writer.bytes[i];
    if (zeros == 2 && byte <= 3) {
      output->push_back(3);
      zeros = 0;
      if (output->size() == kKnownSuffixEnd)
        break;
    }
    output->push_back(byte);
    zeros = byte == 0 ? zeros + 1 : 0;
  }
}

struct Witness {
  std::array<uint8_t, kClearLead> prefix;
  Iv ciphertext;
};

struct SearchState {
  CabacWriter writer;
  Macroblock left;
  int macroblocks_left;
};

bool MatchesKnownBytes(const std::vector<uint8_t>& generated,
                       const std::vector<uint8_t>& encrypted) {
  for (size_t i = 0; i < std::min(generated.size(), kKnownSuffixEnd); ++i) {
    if ((i < kClearLead || i >= kClearLead + 16) &&
        generated[i] != encrypted[i])
      return false;
  }
  return true;
}

}  // namespace

class H264SampleAesIvRecovery::Impl {
 public:
  explicit Impl(const std::vector<uint8_t>& key) : key(key) {}

  bool ProcessNalu(const Nalu& nalu) {
    if (key.size() != 16)
      return false;
    if (!iv.empty())
      return true;
    int id;
    if (nalu.type() == Nalu::H264_SPS) {
      if (parser.ParseSps(nalu, &id) != H264Parser::kOk)
        return false;
      const H264Sps* sps = parser.GetSps(id);
      return sps->pic_width_in_mbs_minus1 >= 0 &&
             sps->pic_width_in_mbs_minus1 < std::numeric_limits<int>::max() &&
             sps->pic_height_in_map_units_minus1 >= 0 &&
             sps->pic_height_in_map_units_minus1 <
                 std::numeric_limits<int>::max();
    }
    if (nalu.type() == Nalu::H264_PPS)
      return parser.ParsePps(nalu, &id) == H264Parser::kOk;
    if (nalu.type() != Nalu::H264_IDRSlice)
      return true;
    if (++slices > 16)
      return false;

    const auto encrypted =
        Unescape(nalu.data(), nalu.header_size() + nalu.payload_size());
    if (encrypted.size() < kKnownSuffixEnd)
      return true;
    Witness witness;
    std::copy_n(encrypted.begin(), witness.prefix.size(),
                witness.prefix.begin());
    std::copy_n(encrypted.begin() + kClearLead, witness.ciphertext.size(),
                witness.ciphertext.begin());
    // Repeated transmission of a NAL is not independent evidence.
    for (const auto& previous : witnesses) {
      if (previous.prefix == witness.prefix &&
          previous.ciphertext == witness.ciphertext)
        return true;
    }
    witnesses.push_back(witness);

    Nalu prefix_nalu;
    if (!prefix_nalu.Initialize(Nalu::kH264, encrypted.data(), kClearLead))
      return true;
    H264SliceHeader header;
    if (parser.ParseSliceHeader(prefix_nalu, &header) != H264Parser::kOk ||
        !header.IsISlice())
      return true;
    const H264Pps* pps = parser.GetPps(header.pic_parameter_set_id);
    const H264Sps* sps =
        pps ? parser.GetSps(pps->seq_parameter_set_id) : nullptr;
    if (!sps || !pps->entropy_coding_mode_flag ||
        pps->num_slice_groups_minus1 || !sps->frame_mbs_only_flag ||
        sps->chroma_format_idc != 1 || sps->bit_depth_luma_minus8 ||
        sps->bit_depth_chroma_minus8 || header.field_pic_flag)
      return true;
    const int64_t width =
        static_cast<int64_t>(sps->pic_width_in_mbs_minus1) + 1;
    const int64_t height =
        static_cast<int64_t>(sps->pic_height_in_map_units_minus1) + 1;
    if (width <= 0 || width > std::numeric_limits<int>::max() || height <= 0 ||
        header.first_mb_in_slice < 0 ||
        header.first_mb_in_slice >= width * height)
      return false;
    const int64_t slice_qp =
        26LL + pps->pic_init_qp_minus26 + header.slice_qp_delta;
    if (slice_qp < 0 || slice_qp > 51)
      return false;
    const int qp = static_cast<int>(slice_qp);
    const size_t header_bits = 8 + header.header_bit_size;
    const size_t cabac_start = (header_bits + 7) / 8;
    if (cabac_start >= kClearLead - 1)
      return true;
    for (size_t bit = header_bits; bit < cabac_start * 8; ++bit) {
      if (((encrypted[bit / 8] >> (7 - bit % 8)) & 1) == 0)
        return true;
    }
    const auto clear_prefix = Unescape(encrypted.data(), kClearLead);
    const auto clear_header = Unescape(encrypted.data(), cabac_start);
    const std::vector<uint8_t> cabac_data(
        clear_prefix.begin() + clear_header.size(), clear_prefix.end());
    CabacReader reader(cabac_data, qp);
    Macroblock last;
    int complete = 0;
    // Neighbors preceding this slice are unavailable (H.264 section 6.4.8).
    // Stay in its first row to avoid assuming unknown top-neighbor states.
    const int row_remaining =
        static_cast<int>(width - header.first_mb_in_slice % width);
    for (; complete < std::min(row_remaining, 64); ++complete) {
      const size_t bin_count = reader.bins.size();
      Macroblock mb;
      if (!ReadMacroblock(&reader, complete ? &last : nullptr,
                          pps->transform_8x8_mode_flag, &mb)) {
        reader.bins.resize(bin_count);
        break;
      }
      if (mb.intra16 && !mb.luma_cbp && mb.chroma_cbp < 2 && !mb.qp_delta &&
          templates.size() < kMaxTemplates)
        templates.insert(mb);
      last = mb;
    }
    if (!complete || templates.empty())
      return true;

    CabacWriter writer(clear_header, qp);
    for (const auto& bin : reader.bins)
      writer.Write(bin.first, bin.second);
    if (!writer.valid)
      return true;
    std::vector<uint8_t> generated;
    generated.reserve(kKnownSuffixEnd);
    Escape(writer, &generated);
    if (!MatchesKnownBytes(generated, encrypted))
      return true;
    AesCbcDecryptor decryptor(kNoPadding);
    Iv zero_decrypted;
    if (!decryptor.InitializeWithIv(key, std::vector<uint8_t>(16)) ||
        !decryptor.Crypt(witness.ciphertext.data(), 16, zero_decrypted.data()))
      return false;

    std::vector<SearchState> pending;
    pending.push_back({std::move(writer), last, row_remaining - complete});
    size_t visited = 0;
    std::set<Iv> found;
    while (!pending.empty() && visited < kMaxSearchStates &&
           total_visited < kMaxTotalSearchStates &&
           found.size() < kMaxCandidates) {
      SearchState state = std::move(pending.back());
      pending.pop_back();
      if (!state.macroblocks_left)
        continue;
      for (const auto& mb : templates) {
        if (++visited > kMaxSearchStates ||
            ++total_visited > kMaxTotalSearchStates)
          break;
        CabacWriter next = state.writer;
        WriteMacroblock(&next, state.left, mb);
        if (!next.valid)
          continue;
        Escape(next, &generated);
        if (!MatchesKnownBytes(generated, encrypted))
          continue;
        if (generated.size() >= kKnownSuffixEnd) {
          Iv candidate;
          for (size_t i = 0; i < candidate.size(); ++i)
            candidate[i] = generated[kClearLead + i] ^ zero_decrypted[i];
          if (!found.insert(candidate).second)
            continue;
        } else {
          pending.push_back({std::move(next), mb, state.macroblocks_left - 1});
        }
      }
    }
    const bool exhausted = pending.empty() && visited < kMaxSearchStates &&
                           total_visited < kMaxTotalSearchStates &&
                           found.size() < kMaxCandidates;
    if (total_visited >= kMaxTotalSearchStates)
      return false;
    // A truncated search cannot establish uniqueness, even if one of its
    // candidates agrees with an earlier slice.
    if (!exhausted || found.empty())
      return true;
    if (completed_witnesses.empty()) {
      common_candidates = std::move(found);
    } else {
      std::set<Iv> intersection;
      std::set_intersection(common_candidates.begin(), common_candidates.end(),
                            found.begin(), found.end(),
                            std::inserter(intersection, intersection.end()));
      common_candidates = std::move(intersection);
    }
    completed_witnesses.push_back(witness);
    if (common_candidates.size() != 1)
      return true;
    // Repeated syntax can have multiple valid continuations. Require a unique
    // common candidate and independent clear prefixes and encrypted blocks.
    for (const auto& previous : completed_witnesses) {
      if (previous.prefix != witness.prefix &&
          previous.ciphertext != witness.ciphertext) {
        const Iv& candidate = *common_candidates.begin();
        iv.assign(candidate.begin(), candidate.end());
        break;
      }
    }
    return true;
  }

  const std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
  H264Parser parser;
  std::set<Macroblock> templates;
  std::vector<Witness> witnesses;
  std::set<Iv> common_candidates;
  std::vector<Witness> completed_witnesses;
  size_t total_visited = 0;
  size_t slices = 0;
};

H264SampleAesIvRecovery::H264SampleAesIvRecovery(
    const std::vector<uint8_t>& key)
    : impl_(new Impl(key)) {}

H264SampleAesIvRecovery::~H264SampleAesIvRecovery() = default;

bool H264SampleAesIvRecovery::ProcessNalu(const Nalu& nalu) {
  return impl_->ProcessNalu(nalu);
}

const std::vector<uint8_t>& H264SampleAesIvRecovery::iv() const {
  return impl_->iv;
}

void H264SampleAesIvRecovery::Reset() {
  impl_.reset(new Impl(impl_->key));
}

}  // namespace media
}  // namespace shaka
