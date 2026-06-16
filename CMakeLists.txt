cmake_minimum_required(VERSION 3.16)

project(emsshd
    VERSION 0.1.0
    LANGUAGES C
)

include(CheckLibraryExists)
include(CheckSymbolExists)

option(EMSSH_BUILD_EXAMPLES "Build emssh examples" ON)
option(EMSSH_BUILD_TESTS "Build emssh tests" ON)
option(EMSSH_USE_MBEDTLS "Build mbedTLS PSA crypto backend" ON)
option(EMSSH_MBEDTLS_LEGACY_EMBED_CORE "For mbedTLS legacy backend, compile vendored TF-PSA-Crypto core sources directly and skip Libs/external/mbedtls CMake" OFF)
option(EMSSH_USE_OPENSSL "Build OpenSSL crypto backend (experimental)" OFF)
option(EMSSH_USE_WOLFSSL "Build wolfSSL crypto backend (experimental)" OFF)
option(EMSSH_USE_LOCAL_WOLFSSL_SOURCE "Prefer Libs/external/wolfssl source when EMSSH_USE_WOLFSSL=ON" ON)
option(EMSSH_BUILD_STDIO_FS "Build stdio/native filesystem adapter" ON)
option(EMSSH_BUILD_PORTABLE_FS "Build portable callback-based filesystem adapter" ON)
option(EMSSH_BUILD_TCP_SOCKET "Build TCP socket network adapter" ON)
option(EMSSH_BUILD_FREERTOS_RUNTIME "Build FreeRTOS runtime adapter (mem/time/log)" OFF)
option(EMSSH_BUILD_LWIP_NET "Build lwIP socket network adapter" OFF)
option(EMSSH_BUILD_POSIX_RUNTIME "Build POSIX runtime adapter (mem/time/log)" OFF)
option(EMSSH_BUILD_POSIX_NET "Build POSIX socket network adapter" OFF)
option(EMSSH_BUILD_POSIX_TERM "Build POSIX PTY terminal adapter" OFF)
option(EMSSH_BUILD_POSIX_PASSWD_AUTH "Build POSIX /etc/passwd password auth adapter" OFF)
set(_emssh_default_mbedtls_legacy_rng_linux OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_emssh_default_mbedtls_legacy_rng_linux ON)
endif()
option(EMSSH_BUILD_MBEDTLS_LEGACY_RNG_LINUX "Build Linux mbedTLS legacy hardware RNG adapter" ${_emssh_default_mbedtls_legacy_rng_linux})
option(EMSSH_BUILD_FATFS_ADAPTER "Build FatFS filesystem adapter" OFF)
option(EMSSH_BUILD_LITTLEFS_ADAPTER "Build littlefs filesystem adapter" OFF)
option(EMSSH_BUILD_OPENSSL_PLATFORM "Build OpenSSL platform assembly helper" OFF)
option(EMSSH_BUILD_WOLFSSL_PLATFORM "Build wolfSSL platform assembly helper" OFF)
option(EMSSH_BUILD_SSHD_CONFIG_FILE "Build sshd_config file parser/apply adapter" ON)
option(EMSSH_BUILD_LINUX_POSIX_STDIO_SERVER "Build linux posix+stdio multi-connection server example" OFF)
option(EMSSH_BUILD_EMTASK "Build emtask persistent multi-task SSH app" OFF)
set(EMSSH_LINUX_POSIX_STDIO_SERVER_BACKEND "auto" CACHE STRING "Backend for linux_posix_stdio_server: auto|mbedtls (legacy only)")
set_property(CACHE EMSSH_LINUX_POSIX_STDIO_SERVER_BACKEND PROPERTY STRINGS auto mbedtls)
set(EMSSH_FREERTOS_CONFIG_DIR "" CACHE PATH "Directory containing FreeRTOSConfig.h")
set(EMSSH_LWIP_CONFIG_DIR "" CACHE PATH "Directory containing lwipopts.h")
option(EMSSH_BUILD_FUZZERS "Build reusable fuzz harnesses" OFF)
option(EMSSH_LIBFUZZER "Build emssh_fuzz_decode with LLVM libFuzzer entrypoint" OFF)
option(EMSSH_ENABLE_OPENSSH_INTEROP_TESTS "Enable optional OpenSSH SFTP interoperability tests" OFF)
option(EMSSH_ENABLE_OPENSSH_TERM_INTEROP_TESTS "Enable optional OpenSSH terminal interoperability tests" OFF)

set(EMSSH_ENABLED_BACKEND_COUNT 0)
if(EMSSH_USE_MBEDTLS)
    math(EXPR EMSSH_ENABLED_BACKEND_COUNT "${EMSSH_ENABLED_BACKEND_COUNT}+1")
endif()
if(EMSSH_USE_OPENSSL)
    math(EXPR EMSSH_ENABLED_BACKEND_COUNT "${EMSSH_ENABLED_BACKEND_COUNT}+1")
endif()
if(EMSSH_USE_WOLFSSL)
    math(EXPR EMSSH_ENABLED_BACKEND_COUNT "${EMSSH_ENABLED_BACKEND_COUNT}+1")
endif()
if(NOT EMSSH_ENABLED_BACKEND_COUNT EQUAL 1)
    message(FATAL_ERROR "Exactly one crypto backend must be enabled (set one of EMSSH_USE_MBEDTLS/EMSSH_USE_OPENSSL/EMSSH_USE_WOLFSSL to ON, others OFF).")
endif()

set(_emssh_default_mbedtls_classic_source "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/library" AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/include/mbedtls")
    set(_emssh_default_mbedtls_classic_source "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls")
endif()
set(_emssh_default_mbedtls_classic_layout OFF)
if(_emssh_default_mbedtls_classic_source AND NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/CMakeLists.txt")
    set(_emssh_default_mbedtls_classic_layout ON)
endif()
set(_emssh_default_mbedtls_use_psa ON)
if(_emssh_default_mbedtls_classic_layout)
    set(_emssh_default_mbedtls_use_psa OFF)
endif()
option(EMSSH_MBEDTLS_USE_PSA "Use PSA-based mbedTLS backend (OFF uses classic mbedTLS APIs)" ${_emssh_default_mbedtls_use_psa})
option(EMSSH_MBEDTLS_CLASSIC_LAYOUT "Use Mbed TLS classic layout (2.x/3.x with library/*.c), skip Libs/external/mbedtls CMake" ${_emssh_default_mbedtls_classic_layout})
set(EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR "${_emssh_default_mbedtls_classic_source}" CACHE PATH "Path to Mbed TLS classic source tree (must contain include/ and library/)")

set(_emssh_default_mbedtls_legacy_config "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/APP/emtask/mbedtls_config_port.h")
    set(_emssh_default_mbedtls_legacy_config "${CMAKE_CURRENT_SOURCE_DIR}/APP/emtask/mbedtls_config_port.h")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/File/mbedtls-legacy/mbedtls_config_port.h")
    set(_emssh_default_mbedtls_legacy_config "${CMAKE_CURRENT_SOURCE_DIR}/File/mbedtls-legacy/mbedtls_config_port.h")
endif()
set(EMSSH_MBEDTLS_LEGACY_CONFIG_FILE "${_emssh_default_mbedtls_legacy_config}" CACHE FILEPATH "Legacy mbedTLS config header file used by EMSSH_MBEDTLS_LEGACY_EMBED_CORE")
if(_emssh_default_mbedtls_legacy_config AND
   EMSSH_MBEDTLS_LEGACY_CONFIG_FILE AND
   NOT EXISTS "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}")
    message(STATUS "EMSSH_MBEDTLS_LEGACY_CONFIG_FILE not found; using ${_emssh_default_mbedtls_legacy_config}")
    set(EMSSH_MBEDTLS_LEGACY_CONFIG_FILE "${_emssh_default_mbedtls_legacy_config}" CACHE FILEPATH "Legacy mbedTLS config header file used by EMSSH_MBEDTLS_LEGACY_EMBED_CORE" FORCE)
endif()

if(EMSSH_MBEDTLS_CLASSIC_LAYOUT)
    if(NOT EMSSH_USE_MBEDTLS)
        message(FATAL_ERROR "EMSSH_MBEDTLS_CLASSIC_LAYOUT requires EMSSH_USE_MBEDTLS=ON")
    endif()
    if(EMSSH_MBEDTLS_USE_PSA)
        message(FATAL_ERROR "EMSSH_MBEDTLS_CLASSIC_LAYOUT requires EMSSH_MBEDTLS_USE_PSA=OFF")
    endif()
    if(NOT EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR OR
       NOT EXISTS "${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/library" OR
       NOT EXISTS "${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/include/mbedtls")
        message(FATAL_ERROR "EMSSH_MBEDTLS_CLASSIC_LAYOUT requires EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR to contain include/mbedtls and library/")
    endif()
    if(EXISTS "${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/tf-psa-crypto/CMakeLists.txt")
        message(FATAL_ERROR "EMSSH_MBEDTLS_CLASSIC_LAYOUT expects Mbed TLS 2.x/3.x classic source tree; provided source looks like Mbed TLS 4.x (contains tf-psa-crypto)")
    endif()
endif()

if(EMSSH_MBEDTLS_LEGACY_EMBED_CORE)
    if(NOT EMSSH_USE_MBEDTLS)
        message(FATAL_ERROR "EMSSH_MBEDTLS_LEGACY_EMBED_CORE requires EMSSH_USE_MBEDTLS=ON")
    endif()
    if(EMSSH_MBEDTLS_USE_PSA)
        message(FATAL_ERROR "EMSSH_MBEDTLS_LEGACY_EMBED_CORE requires EMSSH_MBEDTLS_USE_PSA=OFF")
    endif()
endif()

if(EMSSH_MBEDTLS_CLASSIC_LAYOUT AND EMSSH_MBEDTLS_LEGACY_EMBED_CORE)
    message(FATAL_ERROR "EMSSH_MBEDTLS_CLASSIC_LAYOUT and EMSSH_MBEDTLS_LEGACY_EMBED_CORE are mutually exclusive")
endif()

set(EMSSH_MBEDTLS_CLASSIC_LAYOUT_ACTIVE OFF)
if(EMSSH_USE_MBEDTLS AND EMSSH_MBEDTLS_CLASSIC_LAYOUT)
    set(EMSSH_MBEDTLS_CLASSIC_LAYOUT_ACTIVE ON)
endif()

set(EMSSH_MBEDTLS_LEGACY_EMBED_CORE_ACTIVE OFF)
if(EMSSH_USE_MBEDTLS AND EMSSH_MBEDTLS_LEGACY_EMBED_CORE)
    set(EMSSH_MBEDTLS_LEGACY_EMBED_CORE_ACTIVE ON)
endif()

if(EMSSH_USE_MBEDTLS AND NOT EMSSH_MBEDTLS_LEGACY_EMBED_CORE_ACTIVE AND NOT EMSSH_MBEDTLS_CLASSIC_LAYOUT_ACTIVE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Build Mbed TLS programs" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "Build Mbed TLS tests" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "Do not treat Mbed TLS warnings as errors" FORCE)
    set(TF_PSA_CRYPTO_FATAL_WARNINGS OFF CACHE BOOL "Do not treat TF-PSA-Crypto warnings as errors" FORCE)
    set(GEN_FILES ON CACHE BOOL "Generate Mbed TLS generated sources" FORCE)
    set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "Build Mbed TLS static libraries" FORCE)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "Do not build Mbed TLS shared libraries" FORCE)
    add_subdirectory(Libs/external/mbedtls)
endif()

add_library(emssh STATIC
    $<$<AND:$<BOOL:${EMSSH_USE_MBEDTLS}>,$<BOOL:${EMSSH_MBEDTLS_USE_PSA}>>:src/crypto/mbedtls/ssh_crypto_mbedtls.c>
    $<$<AND:$<BOOL:${EMSSH_USE_MBEDTLS}>,$<NOT:$<BOOL:${EMSSH_MBEDTLS_USE_PSA}>>>:src/crypto/mbedtls/ssh_crypto_mbedtls_legacy.c>
    $<$<BOOL:${EMSSH_USE_MBEDTLS}>:src/crypto/mbedtls/openssh_key.c>
    $<$<BOOL:${EMSSH_USE_OPENSSL}>:src/crypto/openssl/ssh_crypto_openssl.c>
    $<$<BOOL:${EMSSH_USE_WOLFSSL}>:src/crypto/wolfssl/ssh_crypto_wolfssl.c>
    $<$<BOOL:${EMSSH_BUILD_STDIO_FS}>:src/platform/stdio_fs.c>
    $<$<BOOL:${EMSSH_BUILD_PORTABLE_FS}>:src/platform/portable_fs.c>
    $<$<BOOL:${EMSSH_BUILD_TCP_SOCKET}>:src/platform/tcp_socket.c>
    $<$<BOOL:${EMSSH_BUILD_FREERTOS_RUNTIME}>:src/platform/freertos_runtime.c>
    $<$<BOOL:${EMSSH_BUILD_LWIP_NET}>:src/platform/lwip_net.c>
    $<$<BOOL:${EMSSH_BUILD_POSIX_RUNTIME}>:src/platform/posix_runtime.c>
    $<$<BOOL:${EMSSH_BUILD_POSIX_NET}>:src/platform/posix_net.c>
    $<$<BOOL:${EMSSH_BUILD_POSIX_TERM}>:src/platform/posix_term.c>
    $<$<BOOL:${EMSSH_BUILD_POSIX_PASSWD_AUTH}>:src/platform/posix_passwd_auth.c>
    $<$<BOOL:${EMSSH_BUILD_FATFS_ADAPTER}>:src/platform/fatfs_adapter.c>
    $<$<BOOL:${EMSSH_BUILD_LITTLEFS_ADAPTER}>:src/platform/littlefs_adapter.c>
    $<$<BOOL:${EMSSH_BUILD_WOLFSSL_PLATFORM}>:src/platform/wolfssl_platform.c>
    $<$<BOOL:${EMSSH_BUILD_SSHD_CONFIG_FILE}>:src/platform/sshd_config_file.c>
    src/core/ssh_buffer.c
    src/core/ssh_connection.c
    src/core/ssh_kex.c
    src/core/ssh_packet.c
    src/core/ssh_server.c
    src/core/ssh_service.c
    src/core/ssh_transport.c
    src/core/ssh_userauth.c
    src/sftp/sftp.c
    src/sftp/sftp_server.c
)

target_include_directories(emssh
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(emssh PUBLIC c_std_99)

if(EMSSH_BUILD_MBEDTLS_LEGACY_RNG_LINUX)
    add_library(emssh_mbedtls_legacy_rng_linux_obj OBJECT src/platform/mbedtls_legacy_rng_linux.c)
    target_compile_features(emssh_mbedtls_legacy_rng_linux_obj PUBLIC c_std_99)
endif()

if(EMSSH_MBEDTLS_CLASSIC_LAYOUT_ACTIVE)
    file(GLOB EMSSH_MBEDTLS_CLASSIC_CORE_SOURCES "${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/library/*.c")

    if(NOT EMSSH_MBEDTLS_CLASSIC_CORE_SOURCES)
        message(FATAL_ERROR "EMSSH_MBEDTLS_CLASSIC_LAYOUT enabled but no sources found in ${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/library")
    endif()

    add_library(emssh_mbedtls_classic_core STATIC ${EMSSH_MBEDTLS_CLASSIC_CORE_SOURCES})
    target_include_directories(emssh_mbedtls_classic_core
        PUBLIC
            ${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/include
    )
    target_compile_features(emssh_mbedtls_classic_core PUBLIC c_std_99)
    if(EMSSH_BUILD_MBEDTLS_LEGACY_RNG_LINUX)
        target_sources(emssh_mbedtls_classic_core PRIVATE $<TARGET_OBJECTS:emssh_mbedtls_legacy_rng_linux_obj>)
    endif()
    if(WIN32 AND NOT CYGWIN)
        target_link_libraries(emssh_mbedtls_classic_core PUBLIC bcrypt)
    endif()

    if(EMSSH_MBEDTLS_LEGACY_CONFIG_FILE)
        if(NOT EXISTS "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}")
            message(FATAL_ERROR "EMSSH_MBEDTLS_LEGACY_CONFIG_FILE not found: ${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}")
        endif()
        get_filename_component(EMSSH_MBEDTLS_LEGACY_CONFIG_DIR "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}" DIRECTORY)
        get_filename_component(EMSSH_MBEDTLS_LEGACY_CONFIG_NAME "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}" NAME)
        target_include_directories(emssh_mbedtls_classic_core PUBLIC ${EMSSH_MBEDTLS_LEGACY_CONFIG_DIR})
        target_compile_definitions(emssh_mbedtls_classic_core PUBLIC
            MBEDTLS_CONFIG_FILE="${EMSSH_MBEDTLS_LEGACY_CONFIG_NAME}"
        )
    endif()
endif()

if(EMSSH_MBEDTLS_LEGACY_EMBED_CORE_ACTIVE)
    file(GLOB EMSSH_MBEDTLS_LEGACY_BUILTIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/drivers/builtin/src/*.c")
    file(GLOB EMSSH_MBEDTLS_LEGACY_EXTRAS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/extras/*.c")
    file(GLOB EMSSH_MBEDTLS_LEGACY_UTILITIES_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/utilities/*.c")
    file(GLOB EMSSH_MBEDTLS_LEGACY_PLATFORM_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/platform/*.c")

    set(EMSSH_MBEDTLS_LEGACY_CORE_SOURCES
        ${EMSSH_MBEDTLS_LEGACY_BUILTIN_SOURCES}
        ${EMSSH_MBEDTLS_LEGACY_EXTRAS_SOURCES}
        ${EMSSH_MBEDTLS_LEGACY_UTILITIES_SOURCES}
        ${EMSSH_MBEDTLS_LEGACY_PLATFORM_SOURCES}
    )

    if(NOT EMSSH_MBEDTLS_LEGACY_CORE_SOURCES)
        message(FATAL_ERROR "EMSSH_MBEDTLS_LEGACY_EMBED_CORE enabled but no TF-PSA-Crypto legacy sources found")
    endif()

    add_library(emssh_mbedtls_legacy_core STATIC ${EMSSH_MBEDTLS_LEGACY_CORE_SOURCES})
    target_include_directories(emssh_mbedtls_legacy_core
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/include
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/drivers/builtin/include
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/core
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/dispatch
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/extras
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/platform
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/utilities
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/drivers/builtin/src
    )
    target_compile_features(emssh_mbedtls_legacy_core PUBLIC c_std_99)
    target_compile_definitions(emssh_mbedtls_legacy_core PUBLIC MBEDTLS_ALLOW_PRIVATE_ACCESS)
    if(EMSSH_BUILD_MBEDTLS_LEGACY_RNG_LINUX)
        target_sources(emssh_mbedtls_legacy_core PRIVATE $<TARGET_OBJECTS:emssh_mbedtls_legacy_rng_linux_obj>)
    endif()

    if(EMSSH_MBEDTLS_LEGACY_CONFIG_FILE)
        if(NOT EXISTS "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}")
            message(FATAL_ERROR "EMSSH_MBEDTLS_LEGACY_CONFIG_FILE not found: ${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}")
        endif()
        get_filename_component(EMSSH_MBEDTLS_LEGACY_CONFIG_DIR "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}" DIRECTORY)
        get_filename_component(EMSSH_MBEDTLS_LEGACY_CONFIG_NAME "${EMSSH_MBEDTLS_LEGACY_CONFIG_FILE}" NAME)
        target_include_directories(emssh_mbedtls_legacy_core PUBLIC ${EMSSH_MBEDTLS_LEGACY_CONFIG_DIR})
        target_compile_definitions(emssh_mbedtls_legacy_core PUBLIC
            MBEDTLS_CONFIG_FILE="${EMSSH_MBEDTLS_LEGACY_CONFIG_NAME}"
            TF_PSA_CRYPTO_CONFIG_FILE="${EMSSH_MBEDTLS_LEGACY_CONFIG_NAME}"
        )
    endif()
endif()

if(EMSSH_USE_MBEDTLS)
    target_compile_definitions(emssh PUBLIC EMSSH_USE_MBEDTLS=1)
    if(EMSSH_MBEDTLS_CLASSIC_LAYOUT_ACTIVE)
        target_include_directories(emssh PUBLIC
            ${EMSSH_MBEDTLS_CLASSIC_SOURCE_DIR}/include
        )
        if(EMSSH_MBEDTLS_LEGACY_CONFIG_FILE)
            target_include_directories(emssh PUBLIC ${EMSSH_MBEDTLS_LEGACY_CONFIG_DIR})
            target_compile_definitions(emssh PUBLIC MBEDTLS_CONFIG_FILE="${EMSSH_MBEDTLS_LEGACY_CONFIG_NAME}")
        endif()
        target_link_libraries(emssh PUBLIC emssh_mbedtls_classic_core)
    elseif(EMSSH_MBEDTLS_LEGACY_EMBED_CORE_ACTIVE)
        target_include_directories(emssh PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/include
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/drivers/builtin/include
        )
        target_link_libraries(emssh PUBLIC emssh_mbedtls_legacy_core)
    else()
        target_include_directories(emssh PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/include
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/include
            ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/mbedtls/tf-psa-crypto/drivers/builtin/include
        )
        target_link_libraries(emssh PUBLIC TF-PSA-Crypto::tfpsacrypto)
        if(EMSSH_BUILD_MBEDTLS_LEGACY_RNG_LINUX)
            target_sources(emssh PRIVATE $<TARGET_OBJECTS:emssh_mbedtls_legacy_rng_linux_obj>)
        endif()
    endif()
endif()

if(EMSSH_USE_OPENSSL)
    find_package(OpenSSL QUIET COMPONENTS Crypto)
    target_compile_definitions(emssh PUBLIC EMSSH_USE_OPENSSL=1)
    if(OpenSSL_FOUND)
        target_compile_definitions(emssh PUBLIC EMSSH_USE_OPENSSL_REAL=1)
        target_link_libraries(emssh PUBLIC OpenSSL::Crypto)
    else()
        message(WARNING "EMSSH_USE_OPENSSL=ON but OpenSSL::Crypto not found; building openssl backend in stub mode")
    endif()
endif()

if(EMSSH_USE_WOLFSSL)
    set(EMSSH_WOLFSSL_TARGET "")

    if(EMSSH_USE_LOCAL_WOLFSSL_SOURCE AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/wolfssl/CMakeLists.txt")
        set(WOLFSSL_EXAMPLES "no" CACHE STRING "Disable wolfSSL examples in emssh build" FORCE)
        set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "Disable wolfSSL crypt tests in emssh build" FORCE)
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static wolfSSL for emssh" FORCE)
        add_subdirectory(Libs/external/wolfssl EXCLUDE_FROM_ALL)
        if(TARGET wolfssl::wolfssl)
            set(EMSSH_WOLFSSL_TARGET wolfssl::wolfssl)
        elseif(TARGET wolfssl)
            set(EMSSH_WOLFSSL_TARGET wolfssl)
        endif()
    endif()

    find_package(wolfssl QUIET CONFIG)

    if(wolfssl_FOUND)
        if(TARGET wolfssl::wolfssl)
            set(EMSSH_WOLFSSL_TARGET wolfssl::wolfssl)
        elseif(TARGET wolfssl)
            set(EMSSH_WOLFSSL_TARGET wolfssl)
        endif()
    endif()

    if(NOT EMSSH_WOLFSSL_TARGET)
        find_path(WOLFSSL_INCLUDE_DIR NAMES wolfssl/wolfssl.h)
        find_library(WOLFSSL_LIBRARY NAMES wolfssl)
        if(WOLFSSL_INCLUDE_DIR AND WOLFSSL_LIBRARY)
            target_include_directories(emssh PUBLIC ${WOLFSSL_INCLUDE_DIR})
            target_link_libraries(emssh PUBLIC ${WOLFSSL_LIBRARY})
            target_compile_definitions(emssh PUBLIC EMSSH_USE_WOLFSSL=1 EMSSH_USE_WOLFSSL_REAL=1)
            message(STATUS "wolfSSL found via include/library lookup")
        else()
            target_compile_definitions(emssh PUBLIC EMSSH_USE_WOLFSSL=1)
            message(WARNING "EMSSH_USE_WOLFSSL=ON but wolfSSL library not found; building wolfssl backend in stub mode")
        endif()
    else()
        target_compile_definitions(emssh PUBLIC EMSSH_USE_WOLFSSL=1 EMSSH_USE_WOLFSSL_REAL=1)
        target_link_libraries(emssh PUBLIC ${EMSSH_WOLFSSL_TARGET})
    endif()

endif()

if(EMSSH_BUILD_TCP_SOCKET)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_TCP_SOCKET=1)
    if(WIN32 OR CYGWIN)
        target_link_libraries(emssh PUBLIC ws2_32)
    endif()
endif()

if(EMSSH_BUILD_STDIO_FS)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_STDIO_FS=1)
endif()

if(EMSSH_BUILD_FREERTOS_RUNTIME)
    if(NOT EMSSH_FREERTOS_CONFIG_DIR OR NOT EXISTS "${EMSSH_FREERTOS_CONFIG_DIR}/FreeRTOSConfig.h")
        message(FATAL_ERROR "EMSSH_BUILD_FREERTOS_RUNTIME requires EMSSH_FREERTOS_CONFIG_DIR to point to a directory containing FreeRTOSConfig.h")
    endif()
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_FREERTOS_RUNTIME=1)
    target_include_directories(emssh PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/FreeRTOS-Kernel/include
        ${EMSSH_FREERTOS_CONFIG_DIR}
    )
endif()

if(EMSSH_BUILD_LWIP_NET)
    if(NOT EMSSH_LWIP_CONFIG_DIR OR NOT EXISTS "${EMSSH_LWIP_CONFIG_DIR}/lwipopts.h")
        message(FATAL_ERROR "EMSSH_BUILD_LWIP_NET requires EMSSH_LWIP_CONFIG_DIR to point to a directory containing lwipopts.h")
    endif()
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_LWIP_NET=1)
    target_include_directories(emssh PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/lwip/src/include
        ${EMSSH_LWIP_CONFIG_DIR}
    )
endif()

if(EMSSH_BUILD_POSIX_RUNTIME)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_POSIX_RUNTIME=1)
endif()

if(EMSSH_BUILD_POSIX_NET)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_POSIX_NET=1)
endif()

if(EMSSH_BUILD_POSIX_TERM)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_POSIX_TERM=1)
endif()

if(EMSSH_BUILD_POSIX_PASSWD_AUTH)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_POSIX_PASSWD_AUTH=1)
    if(NOT WIN32)
        check_symbol_exists(crypt "crypt.h" EMSSH_HAVE_CRYPT_IN_LIBC)
        if(NOT EMSSH_HAVE_CRYPT_IN_LIBC)
            find_library(EMSSH_CRYPT_LIBRARY crypt)
            if(NOT EMSSH_CRYPT_LIBRARY)
                message(FATAL_ERROR "EMSSH_BUILD_POSIX_PASSWD_AUTH requires crypt() in libc or libcrypt")
            endif()
            target_link_libraries(emssh PUBLIC ${EMSSH_CRYPT_LIBRARY})
        endif()
    endif()
endif()

if(EMSSH_BUILD_FATFS_ADAPTER)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_FATFS_ADAPTER=1)
    target_include_directories(emssh PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/fatfs/include
    )
endif()

if(EMSSH_BUILD_LITTLEFS_ADAPTER)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_LITTLEFS_ADAPTER=1)
    target_include_directories(emssh PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Libs/external/littlefs
    )
endif()

if(EMSSH_BUILD_OPENSSL_PLATFORM)
    if(NOT EMSSH_USE_OPENSSL)
        message(FATAL_ERROR "EMSSH_BUILD_OPENSSL_PLATFORM requires EMSSH_USE_OPENSSL=ON")
    endif()
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_OPENSSL_PLATFORM=1)
endif()

if(EMSSH_BUILD_WOLFSSL_PLATFORM)
    if(NOT EMSSH_USE_WOLFSSL)
        message(FATAL_ERROR "EMSSH_BUILD_WOLFSSL_PLATFORM requires EMSSH_USE_WOLFSSL=ON")
    endif()
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_WOLFSSL_PLATFORM=1)
endif()

if(EMSSH_BUILD_SSHD_CONFIG_FILE)
    target_compile_definitions(emssh PUBLIC EMSSH_BUILD_SSHD_CONFIG_FILE=1)
endif()

if(MSVC)
    target_compile_options(emssh PRIVATE /W4)
    target_compile_definitions(emssh PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(emssh PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(EMSSH_BUILD_EXAMPLES)
    if(EMSSH_USE_MBEDTLS)
        add_executable(emssh_minimal_server examples/minimal_server.c)
        target_link_libraries(emssh_minimal_server PRIVATE emssh)

        add_executable(emssh_concurrent_server examples/concurrent_server.c)
        target_link_libraries(emssh_concurrent_server PRIVATE emssh)
        if(NOT WIN32)
            find_package(Threads REQUIRED)
            target_link_libraries(emssh_concurrent_server PRIVATE Threads::Threads)
        endif()
    endif()

    if(EMSSH_BUILD_FREERTOS_RUNTIME AND EMSSH_BUILD_LWIP_NET AND (EMSSH_BUILD_LITTLEFS_ADAPTER OR EMSSH_BUILD_FATFS_ADAPTER))
        if(EMSSH_USE_MBEDTLS OR EMSSH_USE_OPENSSL OR EMSSH_USE_WOLFSSL)
            add_executable(emssh_embedded_porting_server examples/embedded_porting_server.c)
            target_link_libraries(emssh_embedded_porting_server PRIVATE emssh)

            if(EMSSH_BUILD_LITTLEFS_ADAPTER)
                target_compile_definitions(emssh_embedded_porting_server PRIVATE EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS=1)
            else()
                target_compile_definitions(emssh_embedded_porting_server PRIVATE EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS=0)
            endif()
        endif()
    endif()

    if(EMSSH_BUILD_FREERTOS_RUNTIME AND EMSSH_BUILD_LWIP_NET AND EMSSH_BUILD_FATFS_ADAPTER AND EMSSH_USE_MBEDTLS)
        add_executable(
            emssh_embedded_freertos_lwip_fatfs_mbedtls_server
            examples/embedded_freertos_lwip_fatfs_mbedtls_server.c
        )
        target_link_libraries(emssh_embedded_freertos_lwip_fatfs_mbedtls_server PRIVATE emssh)
    endif()

    if(EMSSH_BUILD_POSIX_RUNTIME AND EMSSH_BUILD_POSIX_NET AND EMSSH_BUILD_STDIO_FS AND (EMSSH_USE_MBEDTLS OR EMSSH_USE_OPENSSL OR EMSSH_USE_WOLFSSL) AND EMSSH_BUILD_SSHD_CONFIG_FILE)
        add_executable(
            emssh_embedded_posix_socket_stdio_openssl_server
            examples/embedded_posix_socket_stdio_openssl_server.c
        )
        target_link_libraries(emssh_embedded_posix_socket_stdio_openssl_server PRIVATE emssh)
    endif()

    if(EMSSH_BUILD_LINUX_POSIX_STDIO_SERVER AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND EMSSH_BUILD_POSIX_RUNTIME AND EMSSH_BUILD_POSIX_NET AND EMSSH_BUILD_STDIO_FS AND EMSSH_BUILD_SSHD_CONFIG_FILE)
        if(NOT EMSSH_USE_MBEDTLS)
            message(FATAL_ERROR "EMSSH_BUILD_LINUX_POSIX_STDIO_SERVER requires EMSSH_USE_MBEDTLS=ON")
        endif()
        if(EMSSH_MBEDTLS_USE_PSA)
            message(FATAL_ERROR "EMSSH_BUILD_LINUX_POSIX_STDIO_SERVER is legacy-only and requires EMSSH_MBEDTLS_USE_PSA=OFF")
        endif()
        if(NOT EMSSH_LINUX_POSIX_STDIO_SERVER_BACKEND STREQUAL "auto" AND
           NOT EMSSH_LINUX_POSIX_STDIO_SERVER_BACKEND STREQUAL "mbedtls")
            message(FATAL_ERROR "EMSSH_BUILD_LINUX_POSIX_STDIO_SERVER is mbedtls-legacy only; set EMSSH_LINUX_POSIX_STDIO_SERVER_BACKEND=auto or mbedtls")
        endif()
        add_executable(
            emssh_linux_posix_stdio_server
            APP/emsshd/Linux/linux_posix_stdio_server.c
        )
        target_link_libraries(emssh_linux_posix_stdio_server PRIVATE emssh)
        target_compile_definitions(emssh_linux_posix_stdio_server PRIVATE EMSSH_LINUX_SERVER_FIXED_BACKEND_MBEDTLS=1)
        if(NOT WIN32)
            find_package(Threads REQUIRED)
            target_link_libraries(emssh_linux_posix_stdio_server PRIVATE Threads::Threads)
        endif()
    endif()

    if(EMSSH_BUILD_EMTASK)
        if(NOT EMSSH_USE_MBEDTLS)
            message(FATAL_ERROR "EMSSH_BUILD_EMTASK requires EMSSH_USE_MBEDTLS=ON")
        endif()
        if(EMSSH_MBEDTLS_USE_PSA)
            message(FATAL_ERROR "EMSSH_BUILD_EMTASK requires EMSSH_MBEDTLS_USE_PSA=OFF")
        endif()
        if(NOT EMSSH_BUILD_TCP_SOCKET)
            message(FATAL_ERROR "EMSSH_BUILD_EMTASK requires EMSSH_BUILD_TCP_SOCKET=ON")
        endif()
        if(NOT EMSSH_BUILD_STDIO_FS)
            message(FATAL_ERROR "EMSSH_BUILD_EMTASK requires EMSSH_BUILD_STDIO_FS=ON")
        endif()
        if(EMSSH_BUILD_POSIX_PASSWD_AUTH AND WIN32)
            message(FATAL_ERROR "EMSSH_BUILD_POSIX_PASSWD_AUTH for emtask is supported only on POSIX/Linux builds")
        endif()
        set(EMTASK_SOURCES
            APP/emtask/emtask.c
        )
        set(EMTASK_IS_WINDOW_CYGWIN OFF)
        set(EMTASK_IS_WINDOW_MSYS2 OFF)
        if(CYGWIN)
            set(EMTASK_IS_WINDOW_CYGWIN ON)
        elseif(WIN32 AND (MINGW OR CMAKE_SYSTEM_NAME MATCHES "MSYS"))
            set(EMTASK_IS_WINDOW_MSYS2 ON)
        endif()
        if(EMTASK_IS_WINDOW_CYGWIN)
            list(APPEND EMTASK_SOURCES APP/emtask/WindowCygwin/emtask_platform_win_cygwin.c)
        elseif(EMTASK_IS_WINDOW_MSYS2)
            list(APPEND EMTASK_SOURCES APP/emtask/WindowMsys2/emtask_platform_win_msys2.c)
        elseif(WIN32)
            list(APPEND EMTASK_SOURCES APP/emtask/WindowMscv/emtask_platform_win.c)
        else()
            list(APPEND EMTASK_SOURCES APP/emtask/Linux/emtask_platform_linux.c)
        endif()
        if(WIN32 OR CYGWIN)
            list(APPEND EMTASK_SOURCES src/platform/window_term.c)
        endif()
        add_executable(
            emtask
            ${EMTASK_SOURCES}
        )
        target_include_directories(emtask PRIVATE APP/emtask)
        target_link_libraries(emtask PRIVATE emssh)
        if(WIN32 OR CYGWIN)
            target_link_libraries(emtask PRIVATE advapi32)
        else()
            find_package(Threads REQUIRED)
            check_library_exists(util forkpty "" EMSSH_HAVE_LIBUTIL)
            if(EMSSH_HAVE_LIBUTIL)
                target_link_libraries(emtask PRIVATE util)
            endif()
            target_link_libraries(emtask PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
        endif()
    endif()
endif()

if(EMSSH_BUILD_TESTS)
    enable_testing()

    add_executable(test_buffer tests/test_buffer.c)
    target_link_libraries(test_buffer PRIVATE emssh)
    add_test(NAME test_buffer COMMAND test_buffer)

    add_executable(test_packet tests/test_packet.c)
    target_link_libraries(test_packet PRIVATE emssh)
    add_test(NAME test_packet COMMAND test_packet)

    add_executable(test_transport tests/test_transport.c)
    target_link_libraries(test_transport PRIVATE emssh)
    add_test(NAME test_transport COMMAND test_transport)

    add_executable(test_kex tests/test_kex.c)
    target_link_libraries(test_kex PRIVATE emssh)
    add_test(NAME test_kex COMMAND test_kex)

    add_executable(test_service tests/test_service.c)
    target_link_libraries(test_service PRIVATE emssh)
    add_test(NAME test_service COMMAND test_service)

    add_executable(test_userauth tests/test_userauth.c)
    target_link_libraries(test_userauth PRIVATE emssh)
    add_test(NAME test_userauth COMMAND test_userauth)

    add_executable(test_connection tests/test_connection.c)
    target_link_libraries(test_connection PRIVATE emssh)
    add_test(NAME test_connection COMMAND test_connection)

    if(EMSSH_BUILD_SSHD_CONFIG_FILE)
        add_executable(test_sshd_config_file tests/test_sshd_config_file.c)
        target_link_libraries(test_sshd_config_file PRIVATE emssh)
        add_test(NAME test_sshd_config_file COMMAND test_sshd_config_file)
    endif()

    add_executable(test_sftp tests/test_sftp.c)
    target_link_libraries(test_sftp PRIVATE emssh)
    add_test(NAME test_sftp COMMAND test_sftp)

    add_executable(test_fuzz_inputs
        tests/test_fuzz_inputs.c
        tests/fuzz/fuzz_decode_common.c
    )
    target_include_directories(test_fuzz_inputs PRIVATE tests/fuzz)
    target_link_libraries(test_fuzz_inputs PRIVATE emssh)
    add_test(NAME test_fuzz_inputs COMMAND test_fuzz_inputs)

    add_executable(test_sftp_server tests/test_sftp_server.c)
    target_link_libraries(test_sftp_server PRIVATE emssh)
    add_test(NAME test_sftp_server COMMAND test_sftp_server)

    if(EMSSH_BUILD_STDIO_FS)
        add_executable(test_stdio_fs tests/test_stdio_fs.c)
        target_link_libraries(test_stdio_fs PRIVATE emssh)
        add_test(NAME test_stdio_fs COMMAND test_stdio_fs)
    endif()

    if(EMSSH_BUILD_PORTABLE_FS)
        add_executable(test_portable_fs tests/test_portable_fs.c)
        target_link_libraries(test_portable_fs PRIVATE emssh)
        add_test(NAME test_portable_fs COMMAND test_portable_fs)
    endif()

    if(EMSSH_BUILD_TCP_SOCKET)
        add_executable(test_tcp_socket tests/test_tcp_socket.c)
        target_link_libraries(test_tcp_socket PRIVATE emssh)
        add_test(NAME test_tcp_socket COMMAND test_tcp_socket)
    endif()

    if(EMSSH_BUILD_POSIX_RUNTIME)
        add_executable(test_posix_runtime tests/test_posix_runtime.c)
        target_link_libraries(test_posix_runtime PRIVATE emssh)
        add_test(NAME test_posix_runtime COMMAND test_posix_runtime)
    endif()

    if(EMSSH_BUILD_POSIX_NET)
        add_executable(test_posix_net tests/test_posix_net.c)
        target_link_libraries(test_posix_net PRIVATE emssh)
        add_test(NAME test_posix_net COMMAND test_posix_net)
    endif()

    if(EMSSH_BUILD_POSIX_TERM)
        add_executable(test_posix_term tests/test_posix_term.c)
        target_link_libraries(test_posix_term PRIVATE emssh)
        add_test(NAME test_posix_term COMMAND test_posix_term)
    endif()

    if(EMSSH_BUILD_POSIX_PASSWD_AUTH)
        add_executable(test_posix_passwd_auth tests/test_posix_passwd_auth.c)
        target_link_libraries(test_posix_passwd_auth PRIVATE emssh)
        add_test(NAME test_posix_passwd_auth COMMAND test_posix_passwd_auth)
    endif()

    if(EMSSH_BUILD_FREERTOS_RUNTIME)
        add_executable(test_freertos_runtime tests/test_freertos_runtime.c)
        target_link_libraries(test_freertos_runtime PRIVATE emssh)
        add_test(NAME test_freertos_runtime COMMAND test_freertos_runtime)
    endif()

    if(EMSSH_USE_MBEDTLS)
        add_executable(test_mbedtls_crypto tests/test_mbedtls_crypto.c)
        target_link_libraries(test_mbedtls_crypto PRIVATE emssh)
        add_test(NAME test_mbedtls_crypto COMMAND test_mbedtls_crypto)

        add_executable(test_mbedtls_openssh_key tests/test_mbedtls_openssh_key.c)
        target_link_libraries(test_mbedtls_openssh_key PRIVATE emssh)
        add_test(NAME test_mbedtls_openssh_key COMMAND test_mbedtls_openssh_key)

        add_executable(test_mbedtls_transport tests/test_mbedtls_transport.c)
        target_link_libraries(test_mbedtls_transport PRIVATE emssh)
        add_test(NAME test_mbedtls_transport COMMAND test_mbedtls_transport)
    endif()

    if(EMSSH_USE_OPENSSL)
        add_executable(test_openssl_crypto tests/test_openssl_crypto.c)
        target_link_libraries(test_openssl_crypto PRIVATE emssh)
        add_test(NAME test_openssl_crypto COMMAND test_openssl_crypto)

        if(EMSSH_BUILD_OPENSSL_PLATFORM)
            add_executable(test_openssl_platform tests/test_openssl_platform.c)
            target_link_libraries(test_openssl_platform PRIVATE emssh)
            add_test(NAME test_openssl_platform COMMAND test_openssl_platform)
        endif()
    endif()

    if(EMSSH_USE_WOLFSSL)
        add_executable(test_wolfssl_crypto tests/test_wolfssl_crypto.c)
        target_link_libraries(test_wolfssl_crypto PRIVATE emssh)
        add_test(NAME test_wolfssl_crypto COMMAND test_wolfssl_crypto)

        if(EMSSH_BUILD_WOLFSSL_PLATFORM)
            add_executable(test_wolfssl_platform tests/test_wolfssl_platform.c)
            target_link_libraries(test_wolfssl_platform PRIVATE emssh)
            add_test(NAME test_wolfssl_platform COMMAND test_wolfssl_platform)
        endif()
    endif()

    if(EMSSH_ENABLE_OPENSSH_INTEROP_TESTS)
        if(NOT EMSSH_BUILD_EXAMPLES OR NOT EMSSH_USE_MBEDTLS OR NOT EMSSH_BUILD_STDIO_FS OR NOT EMSSH_BUILD_TCP_SOCKET)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_INTEROP_TESTS requires examples, mbedTLS, stdio FS, and TCP socket builds")
        endif()

        find_program(POWERSHELL_EXECUTABLE NAMES powershell pwsh)
        find_program(OPENSSH_SFTP_EXECUTABLE NAMES sftp.exe sftp)
        find_program(OPENSSH_SSH_EXECUTABLE NAMES ssh.exe ssh)
        find_program(OPENSSH_KEYGEN_EXECUTABLE NAMES ssh-keygen.exe ssh-keygen)

        if(NOT POWERSHELL_EXECUTABLE)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_INTEROP_TESTS requires powershell or pwsh")
        endif()
        if(NOT OPENSSH_SFTP_EXECUTABLE)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_INTEROP_TESTS requires OpenSSH sftp")
        endif()
        if(NOT OPENSSH_SSH_EXECUTABLE)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_INTEROP_TESTS requires OpenSSH ssh")
        endif()
        if(NOT OPENSSH_KEYGEN_EXECUTABLE)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_INTEROP_TESTS requires OpenSSH ssh-keygen")
        endif()

        add_test(
            NAME interop_probe_ed25519_publickey
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_probe_ed25519.ps1
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -Mode publickey
        )
        add_test(
            NAME interop_probe_ed25519_hostkey
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_probe_ed25519.ps1
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -Mode hostkey
        )
        add_test(
            NAME interop_openssh_sftp_ecdsa
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22227
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
        )
        add_test(
            NAME interop_openssh_sftp_rsa
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22228
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType rsa
        )
        add_test(
            NAME interop_openssh_sftp_rsa_sha1_denied
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22264
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType rsa
                -ForceSshRsaSha1
        )
        add_test(
            NAME interop_openssh_sftp_ed25519
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22263
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ed25519
        )
        add_test(
            NAME interop_openssh_sftp_ed25519_hostkey
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22262
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -ServerHostKeyAlgorithm ed25519
        )
        add_test(
            NAME interop_openssh_sftp_readonly
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22230
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -ReadOnly
        )
        add_test(
            NAME interop_openssh_sftp_from_denied
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22231
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyFrom
        )
        add_test(
            NAME interop_openssh_sftp_from_wildcard
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22232
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -FromPattern 127.0.0.*
        )
        add_test(
            NAME interop_openssh_sftp_multi_connection
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22233
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -RepeatCount 2
                -ServerMaxConnections 2
        )
        add_test(
            NAME interop_openssh_sftp_path_prefix
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22234
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -PathPrefix allowed
        )
        add_test(
            NAME interop_openssh_sftp_path_prefix_multi
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22237
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -PathPrefix "allowed_a,allowed_b"
        )
        add_test(
            NAME interop_openssh_sftp_max_write_end
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22235
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -MaxWriteEnd 8
        )
        add_test(
            NAME interop_openssh_sftp_max_read_end
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22240
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -MaxReadEnd 8192
        )
        add_test(
            NAME interop_openssh_sftp_deny_non_sftp_channel
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22236
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyNonSftpChannel
                -ServerMaxConnections 2
        )
        add_test(
            NAME interop_openssh_sftp_deny_rename
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22238
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyRename
        )
        add_test(
            NAME interop_openssh_sftp_deny_delete
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22239
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyDelete
        )
        add_test(
            NAME interop_openssh_sftp_deny_setstat
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22241
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenySetstat
        )
        add_test(
            NAME interop_openssh_sftp_deny_create
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22242
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyCreate
        )
        add_test(
            NAME interop_openssh_sftp_deny_hardlink
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22243
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyHardlink
        )
        add_test(
            NAME interop_openssh_sftp_deny_remove
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22244
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyRemove
        )
        add_test(
            NAME interop_openssh_sftp_deny_rmdir
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22245
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyRmdir
        )
        add_test(
            NAME interop_openssh_sftp_deny_mkdir
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22246
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyMkdir
        )
        add_test(
            NAME interop_openssh_sftp_deny_open_create
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22247
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyOpenCreate
        )
        add_test(
            NAME interop_openssh_sftp_deny_open_trunc
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22248
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyOpenTrunc
        )
        add_test(
            NAME interop_openssh_sftp_deny_open_append
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22249
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyOpenAppend
        )
        add_test(
            NAME interop_openssh_sftp_deny_open_write
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22250
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyOpenWrite
        )
        add_test(
            NAME interop_openssh_sftp_deny_open_read
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22251
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyOpenRead
        )
        add_test(
            NAME interop_openssh_sftp_deny_read
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22252
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyRead
        )
        add_test(
            NAME interop_openssh_sftp_deny_write
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22253
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyWrite
        )
        add_test(
            NAME interop_openssh_sftp_deny_readdir
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22254
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyReaddir
        )
        add_test(
            NAME interop_openssh_sftp_deny_opendir
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22255
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyOpendir
        )
        add_test(
            NAME interop_openssh_sftp_deny_stat
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22256
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyStat
        )
        add_test(
            NAME interop_openssh_sftp_deny_fstat
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22257
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyFstat
        )
        add_test(
            NAME interop_openssh_sftp_deny_fsetstat
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22261
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyFsetstat
        )
        add_test(
            NAME interop_openssh_sftp_deny_realpath
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22258
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyRealpath
        )
        add_test(
            NAME interop_openssh_sftp_deny_fsync
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22259
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyFsync
        )
        add_test(
            NAME interop_openssh_sftp_deny_statvfs
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22260
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -KeyType ecdsa
                -DenyStatvfs
        )
        add_test(
            NAME interop_openssh_sftp_password
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp.ps1
                -Port 22229
                -ServerExe $<TARGET_FILE:emssh_minimal_server>
                -AuthMode password
        )
        add_test(
            NAME interop_openssh_sftp_concurrent_server
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_sftp_concurrent.ps1
                -Port 22265
                -ServerExe $<TARGET_FILE:emssh_concurrent_server>
                -ParallelClients 2
                -ServerMaxWorkers 2
        )
        set_tests_properties(
            interop_probe_ed25519_publickey
            interop_probe_ed25519_hostkey
            interop_openssh_sftp_ecdsa
            interop_openssh_sftp_rsa
            interop_openssh_sftp_rsa_sha1_denied
            interop_openssh_sftp_ed25519
            interop_openssh_sftp_ed25519_hostkey
            interop_openssh_sftp_readonly
            interop_openssh_sftp_from_denied
            interop_openssh_sftp_from_wildcard
            interop_openssh_sftp_multi_connection
            interop_openssh_sftp_path_prefix
            interop_openssh_sftp_path_prefix_multi
            interop_openssh_sftp_max_read_end
            interop_openssh_sftp_max_write_end
            interop_openssh_sftp_deny_non_sftp_channel
            interop_openssh_sftp_deny_rename
            interop_openssh_sftp_deny_delete
            interop_openssh_sftp_deny_setstat
            interop_openssh_sftp_deny_create
            interop_openssh_sftp_deny_hardlink
            interop_openssh_sftp_deny_remove
            interop_openssh_sftp_deny_rmdir
            interop_openssh_sftp_deny_mkdir
            interop_openssh_sftp_deny_open_create
            interop_openssh_sftp_deny_open_trunc
            interop_openssh_sftp_deny_open_append
            interop_openssh_sftp_deny_open_write
            interop_openssh_sftp_deny_open_read
            interop_openssh_sftp_deny_read
            interop_openssh_sftp_deny_write
            interop_openssh_sftp_deny_readdir
            interop_openssh_sftp_deny_opendir
            interop_openssh_sftp_deny_stat
            interop_openssh_sftp_deny_fstat
            interop_openssh_sftp_deny_fsetstat
            interop_openssh_sftp_deny_realpath
            interop_openssh_sftp_deny_fsync
            interop_openssh_sftp_deny_statvfs
            interop_openssh_sftp_password
            interop_openssh_sftp_concurrent_server
            PROPERTIES RUN_SERIAL TRUE)
    endif()

    if(EMSSH_ENABLE_OPENSSH_TERM_INTEROP_TESTS)
        if(NOT EMSSH_BUILD_EXAMPLES OR
           NOT EMSSH_BUILD_POSIX_RUNTIME OR
           NOT EMSSH_BUILD_POSIX_NET OR
           NOT EMSSH_BUILD_STDIO_FS OR
           NOT EMSSH_BUILD_POSIX_TERM OR
           NOT EMSSH_BUILD_POSIX_PASSWD_AUTH OR
           NOT EMSSH_USE_OPENSSL OR
           NOT EMSSH_BUILD_OPENSSL_PLATFORM)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_TERM_INTEROP_TESTS requires examples, posix runtime/net, stdio FS, posix term, posix passwd auth, and OpenSSL platform build")
        endif()
        if(NOT TARGET emssh_embedded_posix_socket_stdio_openssl_server)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_TERM_INTEROP_TESTS requires target emssh_embedded_posix_socket_stdio_openssl_server")
        endif()

        find_program(POWERSHELL_EXECUTABLE NAMES powershell pwsh)
        find_program(OPENSSH_SSH_EXECUTABLE NAMES ssh.exe ssh)

        if(NOT POWERSHELL_EXECUTABLE)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_TERM_INTEROP_TESTS requires powershell or pwsh")
        endif()
        if(NOT OPENSSH_SSH_EXECUTABLE)
            message(FATAL_ERROR "EMSSH_ENABLE_OPENSSH_TERM_INTEROP_TESTS requires OpenSSH ssh")
        endif()

        add_test(
            NAME interop_openssh_term_shell
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_term.ps1
                -Port 22266
                -ServerExe $<TARGET_FILE:emssh_embedded_posix_socket_stdio_openssl_server>
                -SessionType shell
        )
        add_test(
            NAME interop_openssh_term_exec
            COMMAND ${POWERSHELL_EXECUTABLE}
                -ExecutionPolicy Bypass
                -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop_openssh_term.ps1
                -Port 22267
                -ServerExe $<TARGET_FILE:emssh_embedded_posix_socket_stdio_openssl_server>
                -SessionType exec
        )
        set_tests_properties(
            interop_openssh_term_shell
            interop_openssh_term_exec
            PROPERTIES RUN_SERIAL TRUE)
    endif()
endif()

if(EMSSH_BUILD_FUZZERS)
    add_executable(emssh_fuzz_decode
        tests/fuzz/fuzz_decode_harness.c
        tests/fuzz/fuzz_decode_common.c
    )
    target_include_directories(emssh_fuzz_decode PRIVATE tests/fuzz)
    target_link_libraries(emssh_fuzz_decode PRIVATE emssh)

    if(EMSSH_LIBFUZZER)
        target_compile_definitions(emssh_fuzz_decode PRIVATE EMSSH_LIBFUZZER=1)
        if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(emssh_fuzz_decode PRIVATE -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)
            target_link_options(emssh_fuzz_decode PRIVATE -fsanitize=fuzzer,address,undefined)
            target_compile_options(emssh PRIVATE -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)
        else()
            message(FATAL_ERROR "EMSSH_LIBFUZZER requires a Clang- or GCC-compatible toolchain")
        endif()
    endif()

    if(EMSSH_BUILD_TESTS)
        add_test(
            NAME test_fuzz_decode_corpus
            COMMAND emssh_fuzz_decode
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/seed_ssh_ident.txt
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/seed_kex_algorithms.txt
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/seed_userauth.txt
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/seed_sftp_ops.txt
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/corpus/seed_binary_markers.txt
        )
    endif()
endif()
