# doctest
file(DOWNLOAD
    https://github.com/doctest/doctest/releases/download/v2.4.12/doctest.h
    ${CMAKE_BINARY_DIR}/doctest/doctest.h
    EXPECTED_HASH SHA512=5a69cc6a5e874691877fbd1cea661ec736c2d78d38791cb22a12398c2731ea6d07e7edda4bd1efde2a65df9e4ddd4836f6571d9b04e0241d520790573634065a)

# dlms_parser_test
file(GLOB_RECURSE dlms_parser_test_src_files CONFIGURE_DEPENDS "*.h" "*.cpp")

# Note: Changed to add_executable so the built output can be executed by the build scripts
add_executable(dlms_parser_test ${dlms_parser_test_src_files})

target_include_directories(dlms_parser_test PRIVATE ${CMAKE_BINARY_DIR}/doctest)
target_link_libraries(dlms_parser_test PRIVATE dlms_parser)
target_compile_features(dlms_parser_test PRIVATE cxx_std_20)

#target_link_libraries(dlms_parser_test PRIVATE mbedtls bearssl)
#target_include_directories(dlms_parser_test SYSTEM PUBLIC $<TARGET_PROPERTY:mbedtls,INTERFACE_INCLUDE_DIRECTORIES>) # disable warnings for mbedtls headers

# enable warnings
add_library(dlms_parser_test_warnings INTERFACE)
myproject_set_project_warnings(dlms_parser_test_warnings ON "" "" "" "")
target_link_libraries(dlms_parser_test PRIVATE dlms_parser_test_warnings)

# enable sanitizers: address, leak, undefined behaviour
add_library(dlms_parser_test_sanitizers INTERFACE)
if(WIN32)
  myproject_enable_sanitizers(dlms_parser_test_sanitizers OFF OFF OFF OFF OFF)
else()
  myproject_enable_sanitizers(dlms_parser_test_sanitizers ON ON ON OFF OFF)
endif()
target_link_libraries(dlms_parser_test PRIVATE dlms_parser_test_sanitizers)

# Register the test for CTest
add_test(NAME dlms_parser_test COMMAND dlms_parser_test)