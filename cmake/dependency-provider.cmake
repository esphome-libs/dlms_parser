# Dependency provider for airgapped/offline builds (e.g. COPR mock on EL9/EL10).
#
# Enable with: -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=<path to this file>
#
# DLMS_USE_SYSTEM_DOCTEST / _MBEDTLS / _BEARSSL (default ON)
#   Satisfy each dependency from the system package instead of building it
#   from source. Independent switches: a distro whose system mbedtls is too
#   old for a library feature (e.g. EL9's 2.28 lacks the multi-part PSA AEAD
#   API) can turn off just that one and bundle a newer mbedtls via
#   DLMS_DEPS_SOURCE_ROOT, while still using the system doctest/bearssl.
#   cmake_template isn't listed here: nobody packages it, so a packaging
#   recipe stages it as a source tarball via DLMS_DEPS_SOURCE_ROOT instead.
#
# DLMS_DEPS_SOURCE_ROOT
#   Directory holding pre-populated checkouts, one subdirectory per
#   dependency name (doctest/, mbedtls/, bearssl/, for whichever have the
#   matching DLMS_USE_SYSTEM_* OFF or an unsuccessful system lookup, plus
#   cmake_template/ always), each already at the commit CMakeLists.txt
#   declares. Used instead of the network when set.
#
# With neither satisfying a dependency, the normal networked
# FetchContent fetch proceeds unchanged.

if(CMAKE_VERSION VERSION_LESS "3.24")
  message(FATAL_ERROR "dlms_parser's dependency provider needs CMake >= 3.24")
endif()

include(FetchContent)

option(DLMS_USE_SYSTEM_DOCTEST "Satisfy doctest from the system package" ON)
option(DLMS_USE_SYSTEM_MBEDTLS "Satisfy mbedtls from the system package" ON)
option(DLMS_USE_SYSTEM_BEARSSL "Satisfy bearssl from the system package" ON)
set(DLMS_DEPS_SOURCE_ROOT "" CACHE PATH "Directory of pre-populated dependency checkouts for offline builds")

function(dlms_provide_dependency method dep_name)
  if(NOT method STREQUAL "FETCHCONTENT_MAKEAVAILABLE_SERIAL")
    return()
  endif()

  if(dep_name STREQUAL "doctest" AND DLMS_USE_SYSTEM_DOCTEST)
    find_package(doctest CONFIG QUIET)
    if(doctest_FOUND)
      message(STATUS "dlms_parser: using the system doctest package (${doctest_DIR})")
      FetchContent_SetPopulated(${dep_name})
      return()
    endif()
  endif()

  if(dep_name STREQUAL "mbedtls" AND DLMS_USE_SYSTEM_MBEDTLS)
    find_path(DLMS_MBEDTLS_INCLUDE_DIR mbedtls/gcm.h)
    find_library(DLMS_MBEDTLS_CRYPTO_LIBRARY mbedcrypto)
    if(DLMS_MBEDTLS_INCLUDE_DIR AND DLMS_MBEDTLS_CRYPTO_LIBRARY)
      message(STATUS "dlms_parser: using the system mbedtls package (${DLMS_MBEDTLS_CRYPTO_LIBRARY})")
      # CMakeLists.txt links against a target literally named "mbedtls"
      # and reads its INTERFACE_INCLUDE_DIRECTORIES.
      add_library(mbedtls INTERFACE IMPORTED)
      target_include_directories(mbedtls INTERFACE "${DLMS_MBEDTLS_INCLUDE_DIR}")
      target_link_libraries(mbedtls INTERFACE "${DLMS_MBEDTLS_CRYPTO_LIBRARY}")
      FetchContent_SetPopulated(${dep_name})
      return()
    endif()
  endif()

  if(dep_name STREQUAL "bearssl" AND DLMS_USE_SYSTEM_BEARSSL)
    find_path(DLMS_BEARSSL_INCLUDE_DIR bearssl.h)
    find_library(DLMS_BEARSSL_LIBRARY bearssl)
    if(DLMS_BEARSSL_INCLUDE_DIR AND DLMS_BEARSSL_LIBRARY)
      message(STATUS "dlms_parser: using the system bearssl package (${DLMS_BEARSSL_LIBRARY})")
      # CMakeLists.txt links against a target literally named "bearssl"
      # (and skips its from-source add_library() when this target already exists).
      add_library(bearssl INTERFACE IMPORTED)
      target_include_directories(bearssl INTERFACE "${DLMS_BEARSSL_INCLUDE_DIR}")
      target_link_libraries(bearssl INTERFACE "${DLMS_BEARSSL_LIBRARY}")
      FetchContent_SetPopulated(${dep_name})
      return()
    endif()
  endif()

  if(DLMS_DEPS_SOURCE_ROOT AND EXISTS "${DLMS_DEPS_SOURCE_ROOT}/${dep_name}")
    string(TOUPPER "${dep_name}" dep_name_upper)
    message(STATUS "dlms_parser: using ${DLMS_DEPS_SOURCE_ROOT}/${dep_name} for ${dep_name} (offline)")
    # Not calling FetchContent_SetPopulated(): leave the built-in FetchContent
    # logic to pick up FETCHCONTENT_SOURCE_DIR_* below and proceed offline,
    # honoring the original FetchContent_Declare()'s SOURCE_SUBDIR. This is a
    # CACHE variable, so it survives this function's scope ending.
    set("FETCHCONTENT_SOURCE_DIR_${dep_name_upper}" "${DLMS_DEPS_SOURCE_ROOT}/${dep_name}" CACHE PATH "" FORCE)
  endif()
endfunction()

cmake_language(SET_DEPENDENCY_PROVIDER dlms_provide_dependency SUPPORTED_METHODS FETCHCONTENT_MAKEAVAILABLE_SERIAL)
