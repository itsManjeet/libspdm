cmake_minimum_required(VERSION 3.5)

function(libspdm_make_contiguous_slot_ids COUNT OUT_SLOT_IDS)
    set(SLOT_IDS "")

    if(COUNT GREATER 0)
        math(EXPR MAX_INDEX "${COUNT} - 1")
        foreach(INDEX RANGE ${MAX_INDEX})
            list(APPEND SLOT_IDS ${INDEX})
        endforeach()
    endif()

    set(${OUT_SLOT_IDS} "${SLOT_IDS}" PARENT_SCOPE)
endfunction()

function(libspdm_validate_tpm_slot_ids PREFIX SLOT_IDS OUT_MASK)
    set(SLOTS_SEEN "")
    set(SLOT_MASK_EXPR "")
    set(HAS_SLOT_0 FALSE)

    foreach(SLOT_ID ${SLOT_IDS})
        if(SLOT_ID LESS 0 OR SLOT_ID GREATER 7)
            message(FATAL_ERROR "${PREFIX} slot id ${SLOT_ID} is invalid. Valid SPDM slot IDs are 0..7")
        endif()

        if(";${SLOTS_SEEN};" MATCHES ";${SLOT_ID};")
            message(FATAL_ERROR "${PREFIX} slot id ${SLOT_ID} is duplicated")
        endif()

        if(SLOT_ID EQUAL 0)
            set(HAS_SLOT_0 TRUE)
        endif()

        set(SLOTS_SEEN "${SLOTS_SEEN};${SLOT_ID}")
        if(SLOT_MASK_EXPR STREQUAL "")
            set(SLOT_MASK_EXPR "(1u << ${SLOT_ID})")
        else()
            set(SLOT_MASK_EXPR "${SLOT_MASK_EXPR} | (1u << ${SLOT_ID})")
        endif()
    endforeach()

    if(NOT HAS_SLOT_0)
        message(FATAL_ERROR "${PREFIX} slot ids must include slot 0 because the TPM sample uses slot 0 as the default certificate/signing slot")
    endif()

    set(${OUT_MASK} "(${SLOT_MASK_EXPR})" PARENT_SCOPE)
endfunction()

function(libspdm_tpm_append_measurement_call OUT_VAR MEASUREMENT_INDEX_LITERAL MEASUREMENT_KIND MEASUREMENT_BLOCK_EXPR)
    set(CONTENT "${${OUT_VAR}}")

    if(MEASUREMENT_KIND STREQUAL "PCR")
        set(CONTENT "${CONTENT}    measurement_block_size = libspdm_fill_measurement_pcr_block(\n")
        set(CONTENT "${CONTENT}        use_bit_stream, measurement_hash_algo, ${MEASUREMENT_INDEX_LITERAL},\n")
        set(CONTENT "${CONTENT}        ${MEASUREMENT_BLOCK_EXPR});\n")
    elseif(MEASUREMENT_KIND STREQUAL "SVN")
        set(CONTENT "${CONTENT}    measurement_block_size = libspdm_fill_measurement_svn_block(${MEASUREMENT_BLOCK_EXPR});\n")
    elseif(MEASUREMENT_KIND STREQUAL "HEM")
        set(CONTENT "${CONTENT}    measurement_block_size = libspdm_fill_measurement_hem_block(\n")
        set(CONTENT "${CONTENT}        ${MEASUREMENT_BLOCK_EXPR}, measurement_hash_algo);\n")
    elseif(MEASUREMENT_KIND STREQUAL "MANIFEST")
        set(CONTENT "${CONTENT}    measurement_block_size = libspdm_fill_measurement_manifest_block(${MEASUREMENT_BLOCK_EXPR});\n")
    elseif(MEASUREMENT_KIND STREQUAL "DEVICE_MODE")
        set(CONTENT "${CONTENT}    measurement_block_size = libspdm_fill_measurement_device_mode_block(${MEASUREMENT_BLOCK_EXPR});\n")
    else()
        message(FATAL_ERROR "Unsupported TPM measurement kind ${MEASUREMENT_KIND}")
    endif()

    set(${OUT_VAR} "${CONTENT}" PARENT_SCOPE)
endfunction()

function(libspdm_tpm_append_mel_call OUT_VAR MEASUREMENT_INDEX_LITERAL MEASUREMENT_KIND)
    set(CONTENT "${${OUT_VAR}}")

    if(MEASUREMENT_KIND STREQUAL "PCR")
        set(CONTENT "${CONTENT}    if (!libspdm_tpm_append_pcr_mel_entry(\n")
        set(CONTENT "${CONTENT}            measurement_extension_log, mel_entry, mel_buffer_size,\n")
        set(CONTENT "${CONTENT}            measurement_hash_algo, ${MEASUREMENT_INDEX_LITERAL})) {\n")
        set(CONTENT "${CONTENT}        return false;\n")
        set(CONTENT "${CONTENT}    }\n\n")
    elseif(MEASUREMENT_KIND STREQUAL "SVN")
        set(CONTENT "${CONTENT}    if (!libspdm_tpm_append_svn_mel_entry(\n")
        set(CONTENT "${CONTENT}            measurement_extension_log, mel_entry, mel_buffer_size,\n")
        set(CONTENT "${CONTENT}            ${MEASUREMENT_INDEX_LITERAL})) {\n")
        set(CONTENT "${CONTENT}        return false;\n")
        set(CONTENT "${CONTENT}    }\n\n")
    elseif(MEASUREMENT_KIND STREQUAL "HEM")
        set(CONTENT "${CONTENT}    /* HEM is derived from the MEL, so do not add HEM to the MEL. */\n\n")
    elseif(MEASUREMENT_KIND STREQUAL "MANIFEST")
        set(CONTENT "${CONTENT}    if (!libspdm_tpm_append_manifest_mel_entry(\n")
        set(CONTENT "${CONTENT}            measurement_extension_log, mel_entry, mel_buffer_size,\n")
        set(CONTENT "${CONTENT}            ${MEASUREMENT_INDEX_LITERAL})) {\n")
        set(CONTENT "${CONTENT}        return false;\n")
        set(CONTENT "${CONTENT}    }\n\n")
    elseif(MEASUREMENT_KIND STREQUAL "DEVICE_MODE")
        set(CONTENT "${CONTENT}    if (!libspdm_tpm_append_device_mode_mel_entry(\n")
        set(CONTENT "${CONTENT}            measurement_extension_log, mel_entry, mel_buffer_size,\n")
        set(CONTENT "${CONTENT}            ${MEASUREMENT_INDEX_LITERAL})) {\n")
        set(CONTENT "${CONTENT}        return false;\n")
        set(CONTENT "${CONTENT}    }\n\n")
    else()
        message(FATAL_ERROR "Unsupported TPM measurement kind ${MEASUREMENT_KIND}")
    endif()

    set(${OUT_VAR} "${CONTENT}" PARENT_SCOPE)
endfunction()

function(libspdm_tpm_measurement_kind_macro MEASUREMENT_KIND OUT_VAR)
    if(MEASUREMENT_KIND STREQUAL "PCR")
        set(KIND_MACRO "LIBSPDM_TPM_MEASUREMENT_KIND_PCR")
    elseif(MEASUREMENT_KIND STREQUAL "SVN")
        set(KIND_MACRO "LIBSPDM_TPM_MEASUREMENT_KIND_SVN")
    elseif(MEASUREMENT_KIND STREQUAL "HEM")
        set(KIND_MACRO "LIBSPDM_TPM_MEASUREMENT_KIND_HEM")
    elseif(MEASUREMENT_KIND STREQUAL "MANIFEST")
        set(KIND_MACRO "LIBSPDM_TPM_MEASUREMENT_KIND_MANIFEST")
    elseif(MEASUREMENT_KIND STREQUAL "DEVICE_MODE")
        set(KIND_MACRO "LIBSPDM_TPM_MEASUREMENT_KIND_DEVICE_MODE")
    else()
        message(FATAL_ERROR "Unsupported TPM measurement kind ${MEASUREMENT_KIND}")
    endif()

    set(${OUT_VAR} "${KIND_MACRO}" PARENT_SCOPE)
endfunction()

# Default values for the libspdm TPM sample. The responder sample uses
# non-contiguous SPDM slots 0, 1 and 4, so slot ids are configured separately
# from the handle/certchain values.
set(LIBSPDM_TPM_REQUESTER_HANDLES "0x81000011;0x81000011" CACHE STRING "Semicolon-separated list of TPM Requester Handle Strings")
set(LIBSPDM_TPM_REQUESTER_CERTCHAINS "0x1500011;0x1500011" CACHE STRING "Semicolon-separated list of TPM Requester Certificate Chain NV Indices")
set(LIBSPDM_TPM_RESPONDER_HANDLES "0x81000021;0x81000021;0x81000021" CACHE STRING "Semicolon-separated list of TPM Responder Handle Strings")
set(LIBSPDM_TPM_RESPONDER_CERTCHAINS "0x1500021;0x1500021;0x1500021" CACHE STRING "Semicolon-separated list of TPM Responder Certificate Chain NV Indices")
set(LIBSPDM_TPM_MEASUREMENTS "0x1=pcr;0x2=pcr;0x3=pcr;0x4=pcr;0x10=svn;0x11=hem;0xFD=manifest;0xFE=device_mode" CACHE STRING "Semicolon- or comma-separated TPM measurement entries in index=kind form. Supported kinds: pcr, svn, hem, manifest, device_mode")
set(LIBSPDM_TPM_MANIFEST_VENDOR_ID "0" CACHE STRING "Vendor ID encoded in the generated TPM measurement manifest")
set(LIBSPDM_TPM_SVN "0x7" CACHE STRING "Default TPM SVN value used when LIBSPDM_TPM_SVN_NV_INDEX is not configured")
set(LIBSPDM_TPM_SVN_NV_INDEX "" CACHE STRING "Optional TPM NV index that stores an 8-byte SVN value")
set(LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE "normal" CACHE STRING "TPM sample device operational mode. Supported value: normal")

# Count the number of configured entries (variables are already CMake lists)
list(LENGTH LIBSPDM_TPM_REQUESTER_HANDLES REQUESTER_HANDLE_COUNT)
list(LENGTH LIBSPDM_TPM_REQUESTER_CERTCHAINS REQUESTER_CERTCHAIN_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_HANDLES RESPONDER_HANDLE_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_CERTCHAINS RESPONDER_CERTCHAIN_COUNT)

if(NOT DEFINED LIBSPDM_TPM_REQUESTER_SLOT_IDS)
    libspdm_make_contiguous_slot_ids(${REQUESTER_HANDLE_COUNT} LIBSPDM_TPM_REQUESTER_SLOT_IDS)
endif()

if(NOT DEFINED LIBSPDM_TPM_RESPONDER_SLOT_IDS)
    if(RESPONDER_HANDLE_COUNT EQUAL 3)
        set(LIBSPDM_TPM_RESPONDER_SLOT_IDS "0;1;4")
    else()
        libspdm_make_contiguous_slot_ids(${RESPONDER_HANDLE_COUNT} LIBSPDM_TPM_RESPONDER_SLOT_IDS)
    endif()
endif()

set(LIBSPDM_TPM_REQUESTER_SLOT_IDS "${LIBSPDM_TPM_REQUESTER_SLOT_IDS}" CACHE STRING "Semicolon-separated list of TPM Requester SPDM slot IDs")
set(LIBSPDM_TPM_RESPONDER_SLOT_IDS "${LIBSPDM_TPM_RESPONDER_SLOT_IDS}" CACHE STRING "Semicolon-separated list of TPM Responder SPDM slot IDs")

list(LENGTH LIBSPDM_TPM_REQUESTER_SLOT_IDS REQUESTER_SLOT_COUNT)
list(LENGTH LIBSPDM_TPM_RESPONDER_SLOT_IDS RESPONDER_SLOT_COUNT)

if(REQUESTER_SLOT_COUNT EQUAL 0)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_SLOT_IDS must contain at least slot 0")
endif()

if(RESPONDER_SLOT_COUNT EQUAL 0)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_SLOT_IDS must contain at least slot 0")
endif()

# Validate that slot ids, handles and certchains have matching counts
if(NOT REQUESTER_SLOT_COUNT EQUAL REQUESTER_HANDLE_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_SLOT_IDS and LIBSPDM_TPM_REQUESTER_HANDLES must have the same number of entries")
endif()

if(NOT REQUESTER_SLOT_COUNT EQUAL REQUESTER_CERTCHAIN_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_REQUESTER_SLOT_IDS and LIBSPDM_TPM_REQUESTER_CERTCHAINS must have the same number of entries")
endif()

if(NOT RESPONDER_SLOT_COUNT EQUAL RESPONDER_HANDLE_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_SLOT_IDS and LIBSPDM_TPM_RESPONDER_HANDLES must have the same number of entries")
endif()

if(NOT RESPONDER_SLOT_COUNT EQUAL RESPONDER_CERTCHAIN_COUNT)
    message(FATAL_ERROR "LIBSPDM_TPM_RESPONDER_SLOT_IDS and LIBSPDM_TPM_RESPONDER_CERTCHAINS must have the same number of entries")
endif()

libspdm_validate_tpm_slot_ids("LIBSPDM_TPM_REQUESTER_SLOT_IDS" "${LIBSPDM_TPM_REQUESTER_SLOT_IDS}" REQUESTER_SUPPORTED_SLOT_MASK)
libspdm_validate_tpm_slot_ids("LIBSPDM_TPM_RESPONDER_SLOT_IDS" "${LIBSPDM_TPM_RESPONDER_SLOT_IDS}" RESPONDER_SUPPORTED_SLOT_MASK)

if(NOT LIBSPDM_TPM_MANIFEST_VENDOR_ID MATCHES "^(0[xX][0-9a-fA-F]+|[0-9]+)$")
    message(FATAL_ERROR "LIBSPDM_TPM_MANIFEST_VENDOR_ID must be a decimal or hex value")
endif()

math(EXPR LIBSPDM_TPM_MANIFEST_VENDOR_ID_VALUE "${LIBSPDM_TPM_MANIFEST_VENDOR_ID}")
if((LIBSPDM_TPM_MANIFEST_VENDOR_ID_VALUE LESS 0) OR
   (LIBSPDM_TPM_MANIFEST_VENDOR_ID_VALUE GREATER 65535))
    message(FATAL_ERROR "LIBSPDM_TPM_MANIFEST_VENDOR_ID must fit in uint16_t")
endif()

if(NOT LIBSPDM_TPM_SVN MATCHES "^(0[xX][0-9a-fA-F]+|[0-9]+)$")
    message(FATAL_ERROR "LIBSPDM_TPM_SVN must be a decimal or hex value")
endif()

if((NOT LIBSPDM_TPM_SVN_NV_INDEX STREQUAL "") AND
   (NOT LIBSPDM_TPM_SVN_NV_INDEX MATCHES "^(0[xX][0-9a-fA-F]+|[0-9]+)$"))
    message(FATAL_ERROR "LIBSPDM_TPM_SVN_NV_INDEX must be empty or a decimal or hex value")
endif()

string(TOLOWER "${LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE}" LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE_LOWER)
if(NOT LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE_LOWER STREQUAL "normal")
    message(FATAL_ERROR "LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE currently supports only 'normal'")
endif()

message(STATUS "TPM Configuration:")
message(STATUS "  Requester configured slots: ${LIBSPDM_TPM_REQUESTER_SLOT_IDS}")
message(STATUS "  Responder configured slots: ${LIBSPDM_TPM_RESPONDER_SLOT_IDS}")
message(STATUS "  Measurements: ${LIBSPDM_TPM_MEASUREMENTS}")
message(STATUS "  SVN NV index: ${LIBSPDM_TPM_SVN_NV_INDEX}")
message(STATUS "  Device operational mode: ${LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE_LOWER}")

# Generate keys.h content dynamically
set(KEYS_H_CONTENT "/**\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  Copyright Notice:\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  Copyright 2024-2026 DMTF. All rights reserved.\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT} **/\n\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#pragma once\n\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}/* Auto-generated TPM handle configuration */\n\n")

# Add slot count and supported-slot mask macros
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_REQUESTER_SLOT_COUNT ${REQUESTER_SLOT_COUNT}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_REQUESTER_SUPPORTED_SLOT_MASK ${REQUESTER_SUPPORTED_SLOT_MASK}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_RESPONDER_SLOT_COUNT ${RESPONDER_SLOT_COUNT}\n")
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK ${RESPONDER_SUPPORTED_SLOT_MASK}\n\n")

# Generate requester handle definitions
set(KEYS_H_CONTENT "${KEYS_H_CONTENT}/* TPM Requester Handles */\n")
math(EXPR REQUESTER_MAX_INDEX "${REQUESTER_SLOT_COUNT} - 1")
foreach(INDEX RANGE ${REQUESTER_MAX_INDEX})
    list(GET LIBSPDM_TPM_REQUESTER_SLOT_IDS ${INDEX} SLOT_ID)
    list(GET LIBSPDM_TPM_REQUESTER_HANDLES ${INDEX} HANDLE)
    list(GET LIBSPDM_TPM_REQUESTER_CERTCHAINS ${INDEX} CERTCHAIN)
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_${SLOT_ID} \"handle:${HANDLE}\"\n")
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_REQUESTER_CERTCHAIN_SLOT_${SLOT_ID} ${CERTCHAIN}\n")
endforeach()

set(KEYS_H_CONTENT "${KEYS_H_CONTENT}\n/* TPM Responder Handles */\n")
math(EXPR RESPONDER_MAX_INDEX "${RESPONDER_SLOT_COUNT} - 1")
foreach(INDEX RANGE ${RESPONDER_MAX_INDEX})
    list(GET LIBSPDM_TPM_RESPONDER_SLOT_IDS ${INDEX} SLOT_ID)
    list(GET LIBSPDM_TPM_RESPONDER_HANDLES ${INDEX} HANDLE)
    list(GET LIBSPDM_TPM_RESPONDER_CERTCHAINS ${INDEX} CERTCHAIN)
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_${SLOT_ID} \"handle:${HANDLE}\"\n")
    set(KEYS_H_CONTENT "${KEYS_H_CONTENT}#define LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_${SLOT_ID} ${CERTCHAIN}\n")
endforeach()

# Write the generated keys.h file
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/keys.h "${KEYS_H_CONTENT}")

# Generate the TPM measurement dispatch selected by LIBSPDM_TPM_MEASUREMENTS.
string(REPLACE "," ";" LIBSPDM_TPM_MEASUREMENTS_LIST "${LIBSPDM_TPM_MEASUREMENTS}")
set(MEASUREMENT_VALUES_SEEN "")
set(MEASUREMENT_DISPATCH_CASES "")
set(MEASUREMENT_CONFIGURED_CASES "")
set(MEASUREMENT_TOTAL_SIZE_BODY "")
set(MEASUREMENT_FILL_ALL_BODY "")
set(MEASUREMENT_MEL_BODY "")
set(MEASUREMENT_MANIFEST_ENTRIES "")
set(MEASUREMENT_COUNT 0)

foreach(MEASUREMENT_CONFIG ${LIBSPDM_TPM_MEASUREMENTS_LIST})
    string(STRIP "${MEASUREMENT_CONFIG}" MEASUREMENT_CONFIG)
    if(MEASUREMENT_CONFIG STREQUAL "")
        continue()
    endif()

    string(REGEX MATCH "^([^=]+)=([^=]+)$" MEASUREMENT_CONFIG_MATCH "${MEASUREMENT_CONFIG}")
    if(NOT MEASUREMENT_CONFIG_MATCH)
        message(FATAL_ERROR "LIBSPDM_TPM_MEASUREMENTS entry '${MEASUREMENT_CONFIG}' must use index=kind form, for example 0x1=pcr")
    endif()

    set(MEASUREMENT_INDEX "${CMAKE_MATCH_1}")
    set(MEASUREMENT_KIND "${CMAKE_MATCH_2}")
    string(STRIP "${MEASUREMENT_INDEX}" MEASUREMENT_INDEX)
    string(STRIP "${MEASUREMENT_KIND}" MEASUREMENT_KIND)
    string(TOUPPER "${MEASUREMENT_KIND}" MEASUREMENT_KIND)

    if(NOT MEASUREMENT_INDEX MATCHES "^(0[xX][0-9a-fA-F]+|[0-9]+)$")
        message(FATAL_ERROR "LIBSPDM_TPM_MEASUREMENTS entry '${MEASUREMENT_CONFIG}' has index '${MEASUREMENT_INDEX}', which is not a decimal or hex byte value")
    endif()

    if(NOT ((MEASUREMENT_KIND STREQUAL "PCR") OR
            (MEASUREMENT_KIND STREQUAL "SVN") OR
            (MEASUREMENT_KIND STREQUAL "HEM") OR
            (MEASUREMENT_KIND STREQUAL "MANIFEST") OR
            (MEASUREMENT_KIND STREQUAL "DEVICE_MODE")))
        message(FATAL_ERROR "LIBSPDM_TPM_MEASUREMENTS entry '${MEASUREMENT_CONFIG}' has unsupported kind '${MEASUREMENT_KIND}'. Supported kinds: pcr, svn, hem, manifest, device_mode")
    endif()

    math(EXPR MEASUREMENT_INDEX_VALUE "${MEASUREMENT_INDEX}")
    if((MEASUREMENT_INDEX_VALUE LESS 1) OR (MEASUREMENT_INDEX_VALUE GREATER 255))
        message(FATAL_ERROR "LIBSPDM_TPM_MEASUREMENTS entry '${MEASUREMENT_CONFIG}' must use an index in the range 0x1..0xFF")
    endif()

    if(";${MEASUREMENT_VALUES_SEEN};" MATCHES ";${MEASUREMENT_INDEX_VALUE};")
        message(FATAL_ERROR "LIBSPDM_TPM_MEASUREMENTS contains duplicate index ${MEASUREMENT_INDEX}")
    endif()
    set(MEASUREMENT_VALUES_SEEN "${MEASUREMENT_VALUES_SEEN};${MEASUREMENT_INDEX_VALUE}")

    string(REGEX REPLACE "^0X" "0x" MEASUREMENT_INDEX_LITERAL "${MEASUREMENT_INDEX}")

    set(MEASUREMENT_CONFIGURED_CASES "${MEASUREMENT_CONFIGURED_CASES}    case ${MEASUREMENT_INDEX_LITERAL}:\n")

    set(MEASUREMENT_DISPATCH_CASES "${MEASUREMENT_DISPATCH_CASES}    case ${MEASUREMENT_INDEX_LITERAL}:\n")
    libspdm_tpm_append_measurement_call(MEASUREMENT_DISPATCH_CASES "${MEASUREMENT_INDEX_LITERAL}" "${MEASUREMENT_KIND}" "measurement_block")
    set(MEASUREMENT_DISPATCH_CASES "${MEASUREMENT_DISPATCH_CASES}        return measurement_block_size;\n\n")

    libspdm_tpm_append_measurement_call(MEASUREMENT_TOTAL_SIZE_BODY "${MEASUREMENT_INDEX_LITERAL}" "${MEASUREMENT_KIND}" "NULL")
    set(MEASUREMENT_TOTAL_SIZE_BODY "${MEASUREMENT_TOTAL_SIZE_BODY}    if (measurement_block_size == 0) {\n")
    set(MEASUREMENT_TOTAL_SIZE_BODY "${MEASUREMENT_TOTAL_SIZE_BODY}        return 0;\n")
    set(MEASUREMENT_TOTAL_SIZE_BODY "${MEASUREMENT_TOTAL_SIZE_BODY}    }\n")
    set(MEASUREMENT_TOTAL_SIZE_BODY "${MEASUREMENT_TOTAL_SIZE_BODY}    total_size += measurement_block_size;\n\n")

    libspdm_tpm_append_measurement_call(MEASUREMENT_FILL_ALL_BODY "${MEASUREMENT_INDEX_LITERAL}" "${MEASUREMENT_KIND}" "measurement_block")
    set(MEASUREMENT_FILL_ALL_BODY "${MEASUREMENT_FILL_ALL_BODY}    if (measurement_block_size == 0) {\n")
    set(MEASUREMENT_FILL_ALL_BODY "${MEASUREMENT_FILL_ALL_BODY}        return 0;\n")
    set(MEASUREMENT_FILL_ALL_BODY "${MEASUREMENT_FILL_ALL_BODY}    }\n")
    set(MEASUREMENT_FILL_ALL_BODY "${MEASUREMENT_FILL_ALL_BODY}    total_size += measurement_block_size;\n")
    set(MEASUREMENT_FILL_ALL_BODY "${MEASUREMENT_FILL_ALL_BODY}    measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);\n\n")

    libspdm_tpm_append_mel_call(MEASUREMENT_MEL_BODY "${MEASUREMENT_INDEX_LITERAL}" "${MEASUREMENT_KIND}")
    libspdm_tpm_measurement_kind_macro("${MEASUREMENT_KIND}" MEASUREMENT_KIND_MACRO)
    set(MEASUREMENT_MANIFEST_ENTRIES "${MEASUREMENT_MANIFEST_ENTRIES}        { ${MEASUREMENT_INDEX_LITERAL}, ${MEASUREMENT_KIND_MACRO}, 0 },\n")

    math(EXPR MEASUREMENT_COUNT "${MEASUREMENT_COUNT} + 1")
endforeach()

math(EXPR MEASUREMENT_MANIFEST_SIZE "9 + (${MEASUREMENT_COUNT} * 4)")
if(MEASUREMENT_MANIFEST_SIZE GREATER 65535)
    message(FATAL_ERROR "Generated TPM measurement manifest is too large")
endif()

if(LIBSPDM_TPM_SVN_NV_INDEX STREQUAL "")
    set(LIBSPDM_TPM_SVN_NV_INDEX_ENABLED "0")
    set(LIBSPDM_TPM_SVN_NV_INDEX_VALUE "0")
else()
    set(LIBSPDM_TPM_SVN_NV_INDEX_ENABLED "1")
    set(LIBSPDM_TPM_SVN_NV_INDEX_VALUE "${LIBSPDM_TPM_SVN_NV_INDEX}")
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/meas_data.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/meas_data.h
    @ONLY
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/meas_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/meas_config.h
    @ONLY
)

add_library(spdm_device_secret_lib_tpm STATIC "")

target_include_directories(spdm_device_secret_lib_tpm
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_tpm
        ${LIBSPDM_DIR}/include
        ${LIBSPDM_DIR}/include/hal
        ${LIBSPDM_DIR}/os_stub
)

target_sources(spdm_device_secret_lib_tpm
    PRIVATE
         ../spdm_device_secret_lib_sample/chal.c
        csr.c
        ../spdm_device_secret_lib_sample/endpointinfo.c
        ../spdm_device_secret_lib_sample/event.c
        ../spdm_device_secret_lib_sample/key_ex.c
        ../spdm_device_secret_lib_sample/key_pair.c
        meas.c
        meas_impl.c
        lib.c
        ../spdm_device_secret_lib_sample/psk.c
        read_pub_cert.c
        read_pub_cert_pqc.c
        ../spdm_device_secret_lib_sample/read_special_cert.c
        ../spdm_device_secret_lib_sample/set_cert.c
        sign.c
        ${CMAKE_CURRENT_BINARY_DIR}/keys.h
        ${CMAKE_CURRENT_BINARY_DIR}/meas_data.h
        ${CMAKE_CURRENT_BINARY_DIR}/meas_config.h
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    target_compile_options(spdm_device_secret_lib_tpm PRIVATE -DLIBSPDM_CPU_ARM)
endif()
