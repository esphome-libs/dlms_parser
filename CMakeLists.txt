if(ESP_PLATFORM)
   idf_component_register(SRC_DIRS src INCLUDE_DIRS src)
   return()
endif()

if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR) # used via add_subdirectory
  file(GLOB_RECURSE dlms_parser_src_files CONFIGURE_DEPENDS "src/*.h" "src/*.cpp")
  add_library(dlms_parser ${dlms_parser_src_files})
  target_compile_features(dlms_parser PUBLIC cxx_std_20)
  return()
endif()

cmake_minimum_required(VERSION 3.14)
cmake_policy(SET CMP0092 NEW) # don't add "/W3" to the compilation flags when using MSVC
project(dlms_parser)
include(FetchContent)
set(CMAKE_CXX_SCAN_FOR_MODULES 0) # For clang, module scanning requires "clang-scan-deps". It is not included in some Linux distros.

if(MINGW)
  message(FATAL_ERROR "MinGW is not supported")
endif()

# doctest
file(DOWNLOAD
  https://github.com/doctest/doctest/releases/download/v2.4.12/doctest.h
  ${CMAKE_BINARY_DIR}/doctest/doctest.h
  EXPECTED_HASH SHA512=5a69cc6a5e874691877fbd1cea661ec736c2d78d38791cb22a12398c2731ea6d07e7edda4bd1efde2a65df9e4ddd4836f6571d9b04e0241d520790573634065a)

# mbedtls
FetchContent_Populate(
  mbedtls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2
  URL_HASH SHA256=4a11f1777bb95bf4ad96721cac945a26e04bf19f57d905f241fe77ebeddf46d8)
set(ENABLE_PROGRAMS OFF CACHE INTERNAL "")
set(ENABLE_TESTING OFF CACHE INTERNAL "")
set(MBEDTLS_FATAL_WARNINGS OFF CACHE INTERNAL "")
add_subdirectory(${mbedtls_SOURCE_DIR})

# bearssl
FetchContent_Populate(
  bearssl
  URL https://bearssl.org/bearssl-0.6.tar.gz
  URL_HASH SHA512=f9ed25683cfc6c4abe7f1203a2b82ed101ee4c9e0f9ab60755b6a09c8d1e8e4f64d413624e7bb9c4b0033f909a2e4568a1d916cc6ce4736222900691e1f8359a)
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
  URL https://github.com/cpp-best-practices/cmake_template/archive/0a32e3ff530534f04d7a73817d563bb26eea1b5a.zip
  URL_HASH SHA512=4cab8e5f75054b46c131447e0b9b4f36239eed7c8e5c3a01a09f1454126ea4fc24a5426a4662966cd925673f25383220a56644cab7551cb70aa40870e4577c0b)
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
option(DLMS_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer for dlms_parser" ON)
option(DLMS_ENABLE_SANITIZER_LEAK "Enable leak sanitizer for dlms_parser" ON)
option(DLMS_ENABLE_SANITIZER_UNDEFINED "Enable undefined behavior sanitizer for dlms_parser" ON)

myproject_enable_sanitizers(
  dlms_parser_sanitizers
  ${DLMS_ENABLE_SANITIZER_ADDRESS}
  ${DLMS_ENABLE_SANITIZER_LEAK}
  ${DLMS_ENABLE_SANITIZER_UNDEFINED}
  OFF
  OFF
)
target_link_libraries(dlms_parser PUBLIC dlms_parser_sanitizers)

# dlms_parser_test
file(GLOB_RECURSE dlms_parser_test_src_files CONFIGURE_DEPENDS "tests/*.h" "tests/*.cpp")
add_executable(dlms_parser_test ${dlms_parser_test_src_files})
target_link_libraries(dlms_parser_test PRIVATE dlms_parser dlms_cryptography)
target_include_directories(dlms_parser_test PRIVATE ${CMAKE_BINARY_DIR}/doctest ${CMAKE_CURRENT_SOURCE_DIR} src)
enable_testing()
add_test(NAME dlms_parser_test COMMAND dlms_parser_test)

# decode_readout
add_executable(decode_readout tools/decode_readout.cpp)
target_link_libraries(decode_readout PRIVATE dlms_parser dlms_cryptography)
target_include_directories(decode_readout PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
