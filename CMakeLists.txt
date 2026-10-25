if(ESP_PLATFORM)
   file(GLOB_RECURSE dlms_parser_src_files "src/*.h" "src/*.cpp")
   idf_component_register(SRCS ${dlms_parser_src_files} INCLUDE_DIRS src)
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
option(DLMS_ENABLE_SANITIZERS "Build dlms_parser and its tests with ASan/UBSan" ON)
option(DLMS_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
set(CMAKE_CXX_SCAN_FOR_MODULES 0) # For clang, module scanning requires "clang-scan-deps". It is not included in some Linux distros.

if(MINGW)
  message(FATAL_ERROR "MinGW is not supported")
endif()

# doctest
FetchContent_Declare(
  doctest
  GIT_REPOSITORY https://github.com/doctest/doctest
  GIT_TAG v2.5.3)
FetchContent_MakeAvailable(doctest)
list(APPEND CMAKE_MODULE_PATH "${doctest_SOURCE_DIR}/scripts/cmake" "${doctest_DIR}")
include(doctest)

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
FetchContent_Declare(
  bearssl
  GIT_REPOSITORY https://bearssl.org/git/BearSSL
  GIT_TAG v0.6)
FetchContent_MakeAvailable(bearssl) # BearSSL has no CMakeLists.txt, so this only populates the source dir
if(NOT TARGET bearssl) # a dependency provider may have already defined this as an imported target
  file(GLOB_RECURSE bearssl_sources CONFIGURE_DEPENDS "${bearssl_SOURCE_DIR}/src/*.c")
  add_library(bearssl STATIC ${bearssl_sources})
  target_include_directories(bearssl SYSTEM PUBLIC "${bearssl_SOURCE_DIR}/inc" PRIVATE "${bearssl_SOURCE_DIR}/src")
endif()

# Combine mbedtls and bearssl into a single "crypto" target to simplify linking
add_library(dlms_cryptography INTERFACE)
target_link_libraries(dlms_cryptography INTERFACE mbedtls bearssl)
target_include_directories(dlms_cryptography SYSTEM INTERFACE $<TARGET_PROPERTY:mbedtls,INTERFACE_INCLUDE_DIRECTORIES>) # disable warnings for mbedtls headers

# cmake_template for warnings and sanitizers
FetchContent_Declare(
  cmake_template
  GIT_REPOSITORY https://github.com/cpp-best-practices/cmake_template
  GIT_TAG b86318abbf55a657a11a0cf2acce69f221841b22
  SOURCE_SUBDIR cmake) # no CMakeLists.txt there, so this only populates instead of add_subdirectory-ing the whole template project
FetchContent_MakeAvailable(cmake_template)
include(${cmake_template_SOURCE_DIR}/cmake/CompilerWarnings.cmake)
include(${cmake_template_SOURCE_DIR}/cmake/Sanitizers.cmake)

# dlms_parser library
file(GLOB_RECURSE dlms_parser_src_files CONFIGURE_DEPENDS "src/*.h" "src/*.cpp")
add_library(dlms_parser ${dlms_parser_src_files})
target_compile_features(dlms_parser PUBLIC cxx_std_20)

# enable warnings
add_library(dlms_parser_warnings INTERFACE)
myproject_set_project_warnings(dlms_parser_warnings ${DLMS_WARNINGS_AS_ERRORS} "" "" "" "")
if(NOT MSVC)
  # We use `vsnprintf(buffer.data(), buffer.size(), fmt, args);` inside logging function.
  # Thus this warning is a false positive.
  target_compile_options(dlms_parser_warnings INTERFACE -Wno-format-nonliteral)
endif()
target_link_libraries(dlms_parser PUBLIC dlms_parser_warnings)

# enable sanitizers
add_library(dlms_parser_sanitizers INTERFACE)
myproject_enable_sanitizers(dlms_parser_sanitizers ${DLMS_ENABLE_SANITIZERS} ${DLMS_ENABLE_SANITIZERS} ${DLMS_ENABLE_SANITIZERS} OFF OFF)
target_link_libraries(dlms_parser PUBLIC dlms_parser_sanitizers)
if(MSVC)
  cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH MSVC_TOOLS_DIR)
  file(GLOB ASAN_RUNTIME_FILES "${MSVC_TOOLS_DIR}/clang_rt.asan_dynamic-*")
  file(COPY ${ASAN_RUNTIME_FILES} DESTINATION "${CMAKE_BINARY_DIR}")
endif()

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
