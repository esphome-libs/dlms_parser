if(ESP_PLATFORM)
   idf_component_register(SRC_DIRS src INCLUDE_DIRS src)
   return()
endif()

if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR) # used via add_subdirectory
  file(GLOB_RECURSE dlms_parser_src_files CONFIGURE_DEPENDS "src/*.h" "src/*.cpp")
  add_library(dlms_parser ${dlms_parser_src_files})
  target_compile_features(dlms_parser PUBLIC cxx_std_20)
  target_include_directories(dlms_parser SYSTEM PUBLIC src)
  return()
endif()

cmake_minimum_required(VERSION 3.14)
cmake_policy(SET CMP0092 NEW) # don't add "/W3" to the compilation flags when using MSVC
project(dlms_parser)
enable_testing()
include(FetchContent)
set(CMAKE_CXX_SCAN_FOR_MODULES 0) # For clang, module scanning requires "clang-scan-deps". It is not included in some Linux distros.

if(MINGW)
  message(FATAL_ERROR "MinGW is not supported")
endif()

# doctest
FetchContent_Declare(
  doctest
  GIT_REPOSITORY https://github.com/doctest/doctest
  GIT_TAG v2.5.0)
FetchContent_MakeAvailable(doctest)
include("${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake")

# mbedtls
set(ENABLE_PROGRAMS OFF CACHE INTERNAL "")
set(ENABLE_TESTING OFF CACHE INTERNAL "")
set(MBEDTLS_FATAL_WARNINGS OFF CACHE INTERNAL "")
FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
  GIT_TAG v3.6.5)
FetchContent_MakeAvailable(mbedtls)

# bearssl
FetchContent_Populate(
  bearssl
  GIT_REPOSITORY https://bearssl.org/git/BearSSL
  GIT_TAG v0.6)
file(GLOB_RECURSE bearssl_sources CONFIGURE_DEPENDS "${bearssl_SOURCE_DIR}/src/*.c")
add_library(bearssl STATIC ${bearssl_sources})
target_include_directories(bearssl SYSTEM PUBLIC "${bearssl_SOURCE_DIR}/inc" PRIVATE "${bearssl_SOURCE_DIR}/src")

# Combine mbedtls and bearssl into a single "crypto" target to simplify linking
add_library(dlms_cryptography INTERFACE)
target_link_libraries(dlms_cryptography INTERFACE mbedtls bearssl)
target_include_directories(dlms_cryptography SYSTEM INTERFACE $<TARGET_PROPERTY:mbedtls,INTERFACE_INCLUDE_DIRECTORIES>) # disable warnings for mbedtls headers

# cmake_template for warnings and sanitizers
FetchContent_Populate(
  cmake_template
  GIT_REPOSITORY https://github.com/cpp-best-practices/cmake_template
  GIT_TAG 0a32e3ff530534f04d7a73817d563bb26eea1b5a)
include(${cmake_template_SOURCE_DIR}/cmake/CompilerWarnings.cmake)
include(${cmake_template_SOURCE_DIR}/cmake/Sanitizers.cmake)

# dlms_parser library
file(GLOB_RECURSE dlms_parser_src_files CONFIGURE_DEPENDS "src/*.h" "src/*.cpp")
add_library(dlms_parser ${dlms_parser_src_files})
target_compile_features(dlms_parser PUBLIC cxx_std_20)

# enable warnings
add_library(dlms_parser_warnings INTERFACE)
myproject_set_project_warnings(dlms_parser_warnings ON "" "" "" "")
if(NOT MSVC)
  # We use `vsnprintf(buffer.data(), buffer.size(), fmt, args);` inside logging function.
  # Thus this warning is a false positive.
  target_compile_options(dlms_parser_warnings INTERFACE -Wno-format-nonliteral)
endif()
target_link_libraries(dlms_parser PUBLIC dlms_parser_warnings)

# enable sanitizers
add_library(dlms_parser_sanitizers INTERFACE)
if(APPLE)
  # Leak sanitizer is not supported on Macos:
  #   clang++: error: unsupported option '-fsanitize=leak' for target 'arm64-apple-darwin24.6.0'
  set(ENABLE_SANITIZER_LEAK OFF)
else()
  set(ENABLE_SANITIZER_LEAK ON)
endif()
myproject_enable_sanitizers(dlms_parser_sanitizers ON ${ENABLE_SANITIZER_LEAK} ON OFF OFF)
target_link_libraries(dlms_parser PUBLIC dlms_parser_sanitizers)

# dlms_parser_test
file(GLOB_RECURSE dlms_parser_test_src_files CONFIGURE_DEPENDS "tests/*.h" "tests/*.cpp")
add_executable(dlms_parser_test ${dlms_parser_test_src_files})
target_link_libraries(dlms_parser_test PRIVATE dlms_parser dlms_cryptography doctest::doctest)
target_include_directories(dlms_parser_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} src)
doctest_discover_tests(dlms_parser_test)

# decode_readout
add_executable(decode_readout tools/decode_readout.cpp)
target_link_libraries(decode_readout PRIVATE dlms_parser dlms_cryptography)
target_include_directories(decode_readout PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
