# Copyright 2022 Google LLC. All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# CMake build file to host libpng configuration.

# Turn these features on.
set(PNG_STATIC ON)

# Turn these features off.
set(PNG_HARDWARE_OPTIMIZATIONS OFF)
set(PNG_SHARED OFF)
set(PNG_TESTS OFF)
set(PNG_FRAMEWORK OFF)
set(PNG_DEBUG OFF)

# Don't install anything.
set(SKIP_INSTALL_ALL ON)

# Tell libpng where to find zlib headers.
set(ZLIB_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../zlib/source/")
# Tell libpng where to find zlib library to link to.
if (WIN32)
  set(ZLIB_LIBRARY "${CMAKE_SOURCE_DIR}/build/packager/third_party/zlib/source/build/Release/zlibstatic.lib")
else()
  set(ZLIB_LIBRARY "${CMAKE_SOURCE_DIR}/packager/third_party/zlib/source/libz.a")
endif()
# Tell libpng where to find libm on Linux (-lm).
set(M_LIBRARY m)

# With these set in scope of this folder, load the library's own CMakeLists.txt.
add_subdirectory(source)

# Add missing include directories for users of png_static:
target_include_directories(png_static PUBLIC
  # For png.h, pngconf.h:
  source
  # For pnglibconf.h:
  ${CMAKE_CURRENT_BINARY_DIR}/source)
