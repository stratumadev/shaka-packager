// Copyright 2026 Google LLC. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PACKAGER_MEDIA_CODECS_H264_SAMPLE_AES_IV_RECOVERY_H_
#define PACKAGER_MEDIA_CODECS_H264_SAMPLE_AES_IV_RECOVERY_H_

#include <cstdint>
#include <memory>
#include <vector>

namespace shaka {
namespace media {

class Nalu;

// Bounded recovery for SAMPLE-AES AVC streams that omit their IV. It uses
// observed CABAC macroblock syntax from progressive 8-bit 4:2:0 I-slices and
// requires agreement between independent slices.
// Streams without suitable repeated syntax are not recoverable this way.
class H264SampleAesIvRecovery {
 public:
  explicit H264SampleAesIvRecovery(const std::vector<uint8_t>& key);
  ~H264SampleAesIvRecovery();

  // NALs retain SAMPLE-AES's outer emulation prevention. A successful call may
  // leave iv() empty while more independent evidence is needed.
  bool ProcessNalu(const Nalu& nalu);
  const std::vector<uint8_t>& iv() const;
  void Reset();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace media
}  // namespace shaka

#endif  // PACKAGER_MEDIA_CODECS_H264_SAMPLE_AES_IV_RECOVERY_H_
