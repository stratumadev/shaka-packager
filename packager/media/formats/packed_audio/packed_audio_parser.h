// Copyright 2026 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef PACKAGER_MEDIA_FORMATS_PACKED_AUDIO_PACKED_AUDIO_PARSER_H_
#define PACKAGER_MEDIA_FORMATS_PACKED_AUDIO_PACKED_AUDIO_PARSER_H_

#include <cstdint>
#include <memory>
#include <vector>

#include <packager/media/base/media_parser.h>
#include <packager/media/base/timestamp.h>

namespace shaka {
namespace media {

class AesCbcDecryptor;
class AudioTimestampHelper;
class KeySource;

namespace mp2t {
class Ac3Header;
}

// Incrementally parses HLS Packed Audio segments containing AC-3.  Encrypted
// segments carry their Apple SAMPLE-AES setup in the ID3 audioDescription PRIV
// frame; clear segments contain only the transport-stream timestamp frame.
class PackedAudioParser : public MediaParser {
 public:
  PackedAudioParser();
  ~PackedAudioParser() override;

  void Init(const InitCB& init_cb,
            const NewMediaSampleCB& new_media_sample_cb,
            const NewTextSampleCB& new_text_sample_cb,
            KeySource* decryption_key_source) override;
  [[nodiscard]] bool Flush() override;
  [[nodiscard]] bool Parse(const uint8_t* buf, int size) override;

 private:
  bool ParseAvailable();
  bool ParseId3Tag();
  bool ParseAc3Frame();
  bool EmitStreamInfo(const mp2t::Ac3Header& header);
  bool DecryptAc3Frame(std::vector<uint8_t>* frame);

  InitCB init_cb_;
  NewMediaSampleCB new_media_sample_cb_;
  KeySource* decryption_key_source_ = nullptr;
  std::vector<uint8_t> buffer_;
  size_t buffer_position_ = 0;
  std::unique_ptr<AesCbcDecryptor> decryptor_;
  std::unique_ptr<AudioTimestampHelper> timestamp_helper_;
  std::vector<uint8_t> audio_config_;
  bool initialized_ = false;
  bool have_segment_ = false;
  bool segment_is_encrypted_ = false;
  int64_t next_timestamp_ = 0;
  int64_t last_emitted_timestamp_ = kNoTimestamp;
};

}  // namespace media
}  // namespace shaka

#endif  // PACKAGER_MEDIA_FORMATS_PACKED_AUDIO_PACKED_AUDIO_PARSER_H_
