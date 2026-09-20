// Copyright 2026 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef PACKAGER_MEDIA_FORMATS_PACKED_AUDIO_PACKED_AUDIO_CONSTANTS_H_
#define PACKAGER_MEDIA_FORMATS_PACKED_AUDIO_PACKED_AUDIO_CONSTANTS_H_

namespace shaka {
namespace media {

// Packed audio uses the transport stream timescale.
constexpr double kPackedAudioTimescale = 90000;

// ID3 PRIV owner identifiers for the transport timestamp and SAMPLE-AES setup.
constexpr char kTimestampOwnerIdentifier[] =
    "com.apple.streaming.transportStreamTimestamp";
constexpr char kAudioDescriptionOwnerIdentifier[] =
    "com.apple.streaming.audioDescription";

}  // namespace media
}  // namespace shaka

#endif  // PACKAGER_MEDIA_FORMATS_PACKED_AUDIO_PACKED_AUDIO_CONSTANTS_H_
