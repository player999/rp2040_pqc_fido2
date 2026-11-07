cmake_minimum_required(VERSION 3.13)

# Pico SDK import
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(rp2040_fido2_pqc C CXX ASM)

set(PICO_MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/include/mbedtls_custom_config.h" CACHE STRING "" FORCE)

find_program(PICOTOOL_EXECUTABLE picotool HINTS /home/player999/.local/bin)

pico_sdk_init()

# Configure liboqs for minimal embedded footprint
set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(OQS_MINIMAL_BUILD "KEM_ml_kem_1024;SIG_ml_dsa_87" CACHE STRING "" FORCE)
set(OQS_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
set(OQS_MEMOPT_BUILD ON CACHE BOOL "" FORCE)
set(OQS_PERMIT_UNSUPPORTED_ARCHITECTURE ON CACHE BOOL "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_OPT_TARGET generic CACHE STRING "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../liboqs liboqs EXCLUDE_FROM_ALL)

add_executable(rp2040_fido2_pqc
    src/main.c
    src/status_led.c
    src/user_presence.c
    src/fido_cbor.c
    src/crypto_engine.c
    src/storage.c
    src/ctap_engine.c
    src/fido_hid.c
    src/usb_descriptors.c
)

target_include_directories(rp2040_fido2_pqc PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    $ENV{PICO_SDK_PATH}/lib/mbedtls/include
    $ENV{PICO_SDK_PATH}/lib/mbedtls/include/mbedtls
)

target_compile_definitions(rp2040_fido2_pqc PRIVATE
    MBEDTLS_ALLOW_PRIVATE_ACCESS
    MBEDTLS_NO_PLATFORM_ENTROPY
    MBEDTLS_ENTROPY_HARDWARE_ALT
    PICO_STACK_SIZE=0x1000
    PICO_CORE1_STACK_SIZE=0
)

pico_generate_pio_header(rp2040_fido2_pqc ${CMAKE_CURRENT_LIST_DIR}/src/ws2812.pio)

target_link_libraries(rp2040_fido2_pqc
    pico_stdlib
    pico_rand
    pico_unique_id
    pico_bootrom
    pico_bootsel_via_double_reset
    pico_mbedtls
    hardware_pio
    hardware_clocks
    hardware_sync
    hardware_rosc
    tinyusb_device
    tinyusb_board
    oqs
)

pico_add_extra_outputs(rp2040_fido2_pqc)
