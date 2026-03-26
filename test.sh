#!/usr/bin/env bash
# Run tests with an incremental Debug build.
#
# Usage:
#   ./test.sh                        # build + run all tests
#   ./test.sh "Sagemcom*"            # run only matching test cases
#   ./test.sh "" "XT211"             # run only matching subcases
#
# Options forwarded to the test binary (after --):
#   ./test.sh -- -v                  # verbose output
#   ./test.sh -- --list-test-cases   # list all tests

set -o errexit -o nounset -o pipefail

readonly DIR="$(dirname "$(realpath -s "${BASH_SOURCE[0]}")")"
readonly BUILD_DIR="${DIR}/build/linux-gcc-Debug"
readonly BINARY="${BUILD_DIR}/dlms_parser_test"

tc_filter="${1:-}"
sc_filter="${2:-}"
shift 2 2>/dev/null || true  # eat first two positional args; remainder passed to binary

# Incremental build
export CC=gcc-13
export CXX=g++-13
cmake -S "${DIR}" -B "${BUILD_DIR}" -G Ninja -D CMAKE_BUILD_TYPE=Debug -Q 2>/dev/null \
  || cmake -S "${DIR}" -B "${BUILD_DIR}" -G Ninja -D CMAKE_BUILD_TYPE=Debug
cmake --build "${BUILD_DIR}"

# Build filter args
args=()
[[ -n "${tc_filter}" ]] && args+=("--test-case=${tc_filter}")
[[ -n "${sc_filter}" ]] && args+=("--subcase=${sc_filter}")
args+=("$@")

"${BINARY}" "${args[@]}"
