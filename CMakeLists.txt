if(ESP_PLATFORM)
   idf_component_register(SRC_DIRS src INCLUDE_DIRS src)
   return()
endif()

cmake_minimum_required(VERSION 3.28)
cmake_policy(SET CMP0092 NEW) # don't add "/W3" to the compilation flags when using MSVC
project(dlms_parser)
include(FetchContent)
set(CMAKE_CXX_SCAN_FOR_MODULES 0) # For clang, module scanning requires "clang-scan-deps". It is not included in some Linux distros.

# doctest
file(DOWNLOAD
  https://github.com/doctest/doctest/releases/download/v2.4.12/doctest.h
  ${CMAKE_BINARY_DIR}/doctest/doctest.h
  EXPECTED_HASH SHA512=5a69cc6a5e874691877fbd1cea661ec736c2d78d38791cb22a12398c2731ea6d07e7edda4bd1efde2a65df9e4ddd4836f6571d9b04e0241d520790573634065a)

# mbedtls
FetchContent_Populate(
  mded_tls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.0.0/mbedtls-4.0.0.tar.bz2
  URL_HASH SHA512=cc62c99a82f2f85ee4caa6488804648e81358e59f1498b6a97b034114e531bf44b05ae3d50db797ada939b6d4ac90bde29cd2363a36631af9e5fdfef57bfb267)
set(ENABLE_PROGRAMS OFF CACHE INTERNAL "")
set(ENABLE_TESTING OFF CACHE INTERNAL "")
set(MBEDTLS_FATAL_WARNINGS OFF CACHE INTERNAL "")
add_subdirectory(${mded_tls_SOURCE_DIR})

# bearssl
FetchContent_Populate(
  bearsll
  URL https://bearssl.org/bearssl-0.6.tar.gz
  URL_HASH SHA512=f9ed25683cfc6c4abe7f1203a2b82ed101ee4c9e0f9ab60755b6a09c8d1e8e4f64d413624e7bb9c4b0033f909a2e4568a1d916cc6ce4736222900691e1f8359a)
file(GLOB_RECURSE bearssl_sources CONFIGURE_DEPENDS "${bearsll_SOURCE_DIR}/src/*.c")
add_library(bearssl STATIC ${bearssl_sources})
target_include_directories(bearssl SYSTEM PUBLIC "${bearsll_SOURCE_DIR}/inc" PRIVATE "${bearsll_SOURCE_DIR}/src")

# cmake_template for warnings and sanitizers
FetchContent_Populate(
  cmake_template
  URL https://github.com/cpp-best-practices/cmake_template/archive/0a32e3ff530534f04d7a73817d563bb26eea1b5a.zip
  URL_HASH SHA512=4cab8e5f75054b46c131447e0b9b4f36239eed7c8e5c3a01a09f1454126ea4fc24a5426a4662966cd925673f25383220a56644cab7551cb70aa40870e4577c0b)
include(${cmake_template_SOURCE_DIR}/cmake/CompilerWarnings.cmake)
include(${cmake_template_SOURCE_DIR}/cmake/Sanitizers.cmake)

# dlms_parser_test
file(GLOB_RECURSE dlms_parser_test_src_files CONFIGURE_DEPENDS "src/*.h" "src/*.cpp" "tests/*.h" "tests/*.cpp")
add_executable(dlms_parser_test ${dlms_parser_test_src_files})
target_include_directories(dlms_parser_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} src ${CMAKE_BINARY_DIR}/doctest)
target_compile_features(dlms_parser_test PRIVATE cxx_std_20)
target_link_libraries(dlms_parser_test PRIVATE mbedtls bearssl)
target_include_directories(dlms_parser_test SYSTEM PUBLIC $<TARGET_PROPERTY:mbedtls,INTERFACE_INCLUDE_DIRECTORIES>) # disable warnings for mbedtls headers

# enable warnings
add_library(dlms_parser_test_warnings INTERFACE)
myproject_set_project_warnings(dlms_parser_test_warnings ON "" "" "" "")
target_link_libraries(dlms_parser_test PRIVATE dlms_parser_test_warnings)

# enable sanitizers: address, leak, undefined behaviour
if(NOT MINGW) # The default MinGW toolchain that comes with Clion on Windows doesn't support sanitizers
  add_library(dlms_parser_test_sanitizers INTERFACE)
  myproject_enable_sanitizers(dlms_parser_test_sanitizers ON ON ON OFF OFF)
  target_link_libraries(dlms_parser_test PRIVATE dlms_parser_test_sanitizers)
endif()
