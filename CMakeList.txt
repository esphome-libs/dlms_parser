cmake_minimum_required(VERSION 3.10)
project(dlms_parser)

set(CMAKE_CXX_STANDARD 11)

# Main library
file(GLOB_RECURSE SOURCES "src/dlms_parser/*.cpp")
add_library(dlms_parser STATIC ${SOURCES})
target_include_directories(dlms_parser PUBLIC src)