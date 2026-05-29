// Copyright 2026 Google LLC. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <iostream>
#include <clocale>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#if defined(OS_WIN)
#include <codecvt>
#include <functional>
#endif  // defined(OS_WIN)

#include <absl/log/initialize.h>
#include <absl/log/log.h>
#include <absl/strings/match.h>
#include <absl/strings/str_split.h>

#include <packager/chunking_params.h>
#include <packager/crypto_params.h>
#include <packager/file.h>
#include <packager/kv_pairs/kv_pairs.h>
#include <packager/media/base/container_names.h>
#include <packager/media/base/media_handler.h>
#include <packager/media/base/muxer.h>
#include <packager/media/base/muxer_options.h>
#include <packager/media/base/raw_key_source.h>
#include <packager/media/chunking/chunking_handler.h>
#include <packager/media/demuxer/demuxer.h>
#include <packager/media/formats/mp4/mp4_muxer.h>
#if !defined(SHAKA_DECRYPT)
#include <packager/media/formats/webm/webm_muxer.h>
#endif
#include <packager/macros/status.h>
#include <packager/status.h>
#include <packager/utils/hex_parser.h>

namespace shaka {
namespace {

struct DecryptStreamDescriptor {
  std::string input;
  std::string stream_selector;
  std::string output;
  std::string input_format;
  std::string output_format;
};

struct CommandLine {
  DecryptStreamDescriptor stream;
  RawKeyParams raw_key;
  bool enable_raw_key_decryption = false;
  bool quiet = false;
};

void PrintUsage(const char* program) {
  std::cerr
      << "Usage: " << program
      << " input=<file>,stream=<audio|video|n>,output=<file> "
         "--enable_raw_key_decryption --keys key_id=<kid>:key=<key>\n";
}

std::optional<DecryptStreamDescriptor> ParseStreamDescriptor(
    const std::string& descriptor_string) {
  DecryptStreamDescriptor descriptor;
  std::vector<KVPair> kv_pairs =
      SplitStringIntoKeyValuePairs(descriptor_string, '=', ',');
  if (kv_pairs.empty()) {
    LOG(ERROR) << "Invalid stream descriptor: " << descriptor_string;
    return std::nullopt;
  }

  for (const auto& pair : kv_pairs) {
    if (pair.first == "input" || pair.first == "in") {
      descriptor.input = pair.second;
    } else if (pair.first == "stream" || pair.first == "stream_selector") {
      descriptor.stream_selector = pair.second;
    } else if (pair.first == "output" || pair.first == "out") {
      descriptor.output = pair.second;
    } else if (pair.first == "input_format") {
      descriptor.input_format = pair.second;
    } else if (pair.first == "output_format" || pair.first == "format") {
      descriptor.output_format = pair.second;
    } else {
      LOG(ERROR) << "Unsupported decrypt stream field: " << pair.first;
      return std::nullopt;
    }
  }

  if (descriptor.input.empty() || descriptor.stream_selector.empty() ||
      descriptor.output.empty()) {
    LOG(ERROR) << "Decrypt stream requires input, stream and output.";
    return std::nullopt;
  }
  return descriptor;
}

bool ParseKey(const std::string& key_string, RawKeyParams* raw_key) {
  std::vector<KVPair> pairs =
      SplitStringIntoKeyValuePairs(key_string, '=', ':');
  std::map<std::string, std::string> values;
  for (const auto& pair : pairs)
    values[pair.first] = pair.second;

  const std::string& key_id_hex = values["key_id"];
  const std::string& key_hex = values["key"];
  if (key_id_hex.empty() || key_hex.empty()) {
    LOG(ERROR) << "--keys must contain key_id and key.";
    return false;
  }

  RawKeyParams::KeyInfo key_info;
  if (!ValidHexStringToBytes(key_id_hex, &key_info.key_id)) {
    LOG(ERROR) << "Invalid key_id hex string: " << key_id_hex;
    return false;
  }
  if (!ValidHexStringToBytes(key_hex, &key_info.key)) {
    LOG(ERROR) << "Invalid key hex string: " << key_hex;
    return false;
  }
  if (!values["iv"].empty() &&
      !ValidHexStringToBytes(values["iv"], &key_info.iv)) {
    LOG(ERROR) << "Invalid IV hex string: " << values["iv"];
    return false;
  }

  raw_key->key_map[key_id_hex] = std::move(key_info);
  return true;
}

std::optional<CommandLine> ParseCommandLine(int argc, char** argv) {
  CommandLine command_line;
  bool saw_stream_descriptor = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--enable_raw_key_decryption") {
      command_line.enable_raw_key_decryption = true;
    } else if (arg == "--quiet") {
      command_line.quiet = true;
    } else if (arg == "--keys") {
      if (++i == argc) {
        LOG(ERROR) << "--keys requires a value.";
        return std::nullopt;
      }
      if (!ParseKey(argv[i], &command_line.raw_key))
        return std::nullopt;
    } else if (absl::StartsWith(arg, "--keys=")) {
      if (!ParseKey(arg.substr(std::string("--keys=").size()),
                    &command_line.raw_key)) {
        return std::nullopt;
      }
    } else if (arg == "--help" || arg == "-h") {
      return std::nullopt;
    } else if (!absl::StartsWith(arg, "--") && !saw_stream_descriptor) {
      std::optional<DecryptStreamDescriptor> stream =
          ParseStreamDescriptor(arg);
      if (!stream)
        return std::nullopt;
      command_line.stream = *stream;
      saw_stream_descriptor = true;
    } else {
      LOG(ERROR) << "Unsupported decrypt argument: " << arg;
      return std::nullopt;
    }
  }

  if (!saw_stream_descriptor) {
    LOG(ERROR) << "Missing stream descriptor.";
    return std::nullopt;
  }
  if (!command_line.enable_raw_key_decryption) {
    LOG(ERROR) << "Only raw key decryption is supported.";
    return std::nullopt;
  }
  if (command_line.raw_key.key_map.empty()) {
    LOG(ERROR) << "At least one --keys entry is required.";
    return std::nullopt;
  }
  return command_line;
}

media::MediaContainerName GetOutputFormat(const DecryptStreamDescriptor& stream) {
  if (!stream.output_format.empty())
    return media::DetermineContainerFromFormatName(stream.output_format);
  return media::DetermineContainerFromFileName(stream.output);
}

std::shared_ptr<media::Muxer> CreateMuxer(
    const DecryptStreamDescriptor& stream) {
  media::MuxerOptions options;
  options.output_file_name = stream.output;

  switch (GetOutputFormat(stream)) {
    case media::CONTAINER_MOV:
      return std::make_shared<media::mp4::MP4Muxer>(options);
#if !defined(SHAKA_DECRYPT)
    case media::CONTAINER_WEBM:
      return std::make_shared<media::webm::WebMMuxer>(options);
#endif
    default:
#if defined(SHAKA_DECRYPT)
      LOG(ERROR) << "Only MP4/MOV/M4V/M4A/M4S outputs are supported.";
#else
      LOG(ERROR) << "Only MP4/MOV/M4V/M4A/M4S and WebM outputs are supported.";
#endif
      return nullptr;
  }
}

Status Decrypt(const CommandLine& command_line) {
  std::shared_ptr<media::Demuxer> demuxer =
      std::make_shared<media::Demuxer>(command_line.stream.input);
  demuxer->set_input_format(command_line.stream.input_format);

  std::unique_ptr<media::RawKeySource> key_source =
      media::RawKeySource::Create(command_line.raw_key);
  if (!key_source) {
    return Status(error::INVALID_ARGUMENT, "Invalid raw key parameters.");
  }
  demuxer->SetKeySource(std::move(key_source));

  ChunkingParams chunking_params;
  chunking_params.segment_duration_in_seconds = 6.0;
  std::shared_ptr<media::ChunkingHandler> chunker =
      std::make_shared<media::ChunkingHandler>(chunking_params);
  std::shared_ptr<media::Muxer> muxer = CreateMuxer(command_line.stream);
  if (!muxer) {
    return Status(error::INVALID_ARGUMENT, "Failed to create muxer.");
  }

  RETURN_IF_ERROR(media::MediaHandler::Chain({chunker, muxer}));
  RETURN_IF_ERROR(
      demuxer->SetHandler(command_line.stream.stream_selector, chunker));
  RETURN_IF_ERROR(demuxer->Initialize());
  RETURN_IF_ERROR(demuxer->Run());

  const int64_t output_size =
      File::GetFileSize(command_line.stream.output.c_str());
  if (output_size <= 0) {
    return Status(error::MUXER_FAILURE,
                  "Decryption produced no output file: " +
                      command_line.stream.output +
                      ". The input may not contain a usable stream for the "
                      "selected stream type.");
  }
  return Status::OK;
}

int DecryptMain(int argc, char** argv) {
  absl::InitializeLog();

  std::optional<CommandLine> command_line = ParseCommandLine(argc, argv);
  if (!command_line) {
    PrintUsage(argv[0]);
    return 1;
  }

  Status status = Decrypt(*command_line);
  if (!status.ok()) {
    LOG(ERROR) << "Decryption failed: " << status.ToString();
    return 2;
  }
  if (!command_line->quiet)
    std::cout << "Decryption completed successfully.\n";
  return 0;
}

}  // namespace
}  // namespace shaka

#if defined(OS_WIN)
int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
  std::unique_ptr<char*[], std::function<void(char**)>> utf8_argv(
      new char*[argc], [argc](char** utf8_args) {
        for (int idx = 0; idx < argc; ++idx)
          delete[] utf8_args[idx];
        delete[] utf8_args;
      });
  std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

  for (int idx = 0; idx < argc; ++idx) {
    std::string utf8_arg(converter.to_bytes(argv[idx]));
    utf8_arg += '\0';
    utf8_argv[idx] = new char[utf8_arg.size()];
    memcpy(utf8_argv[idx], utf8_arg.data(), utf8_arg.size());
  }

  std::setlocale(LC_ALL, ".UTF8");
  return shaka::DecryptMain(argc, utf8_argv.get());
}
#else
int main(int argc, char** argv) {
  return shaka::DecryptMain(argc, argv);
}
#endif  // defined(OS_WIN)
