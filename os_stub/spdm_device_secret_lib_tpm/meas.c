/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <base.h>
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_common_lib.h"
#include "meas_impl.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP)

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000
uint8_t m_libspdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) */

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
static bool libspdm_tpm_append_mel_entry(
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log,
    spdm_mel_entry_dmtf_t **mel_entry,
    size_t mel_buffer_size,
    uint8_t measurements_index,
    uint8_t measurement_value_type,
    const void *measurement_value,
    size_t measurement_value_size)
{
    spdm_mel_entry_dmtf_t *entry;
    size_t offset;
    size_t entry_size;

    if (measurement_value_size > UINT16_MAX) {
        return false;
    }

    if (mel_buffer_size < sizeof(spdm_measurement_extension_log_dmtf_t)) {
        return false;
    }

    offset = sizeof(spdm_measurement_extension_log_dmtf_t) +
             measurement_extension_log->mel_entries_len;
    entry_size = sizeof(spdm_mel_entry_dmtf_t) + measurement_value_size;
    if ((offset > mel_buffer_size) || (entry_size > (mel_buffer_size - offset))) {
        return false;
    }

    entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log + offset);
    entry->mel_index = measurement_extension_log->number_of_entries + 1;
    entry->meas_index = measurements_index;
    libspdm_write_uint24(entry->reserved, 0);
    entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        measurement_value_type;
    entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)measurement_value_size;
    libspdm_copy_mem((void *)(entry + 1), measurement_value_size,
                     measurement_value, measurement_value_size);

    measurement_extension_log->number_of_entries++;
    measurement_extension_log->mel_entries_len += (uint32_t)entry_size;

    if (mel_entry != NULL) {
        *mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)entry + entry_size);
    }

    return true;
}

static bool libspdm_tpm_append_pcr_mel_entry(
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log,
    spdm_mel_entry_dmtf_t **mel_entry,
    size_t mel_buffer_size,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index)
{
    size_t hash_size;
    size_t buffer_size;
    uint8_t pcr_digest[LIBSPDM_MAX_HASH_SIZE];

    if (measurement_hash_algo ==
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) {
        return true;
    }

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    if ((hash_size == 0) || (hash_size > sizeof(pcr_digest))) {
        return true;
    }

    buffer_size = hash_size;
    if (!libspdm_tpm_read_pcr(measurement_hash_algo, (uint32_t)(measurements_index - 1),
                              pcr_digest, &buffer_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to read pcr from TPM"));
        return true;
    }

    if (buffer_size != hash_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "hash_size (%d) != buffer_size (%d)\n",
                       (int)hash_size, (int)buffer_size));
        return true;
    }

    return libspdm_tpm_append_mel_entry(
        measurement_extension_log, mel_entry, mel_buffer_size, measurements_index,
        (uint8_t)(measurements_index - 1), pcr_digest, hash_size);
}

static bool libspdm_tpm_append_svn_mel_entry(
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log,
    spdm_mel_entry_dmtf_t **mel_entry,
    size_t mel_buffer_size,
    uint8_t measurements_index)
{
    spdm_measurements_secure_version_number_t svn;

    if (!libspdm_tpm_get_svn(&svn)) {
        return false;
    }

    return libspdm_tpm_append_mel_entry(
        measurement_extension_log, mel_entry, mel_buffer_size, measurements_index,
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM,
        &svn, sizeof(svn));
}

static bool libspdm_tpm_append_manifest_mel_entry(
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log,
    spdm_mel_entry_dmtf_t **mel_entry,
    size_t mel_buffer_size,
    uint8_t measurements_index)
{
    const void *manifest;
    size_t manifest_size;

    manifest = libspdm_tpm_get_measurement_manifest(&manifest_size);

    return libspdm_tpm_append_mel_entry(
        measurement_extension_log, mel_entry, mel_buffer_size, measurements_index,
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM,
        manifest, manifest_size);
}

static bool libspdm_tpm_append_device_mode_mel_entry(
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log,
    spdm_mel_entry_dmtf_t **mel_entry,
    size_t mel_buffer_size,
    uint8_t measurements_index)
{
    spdm_measurements_device_mode_t device_mode;

    libspdm_tpm_get_device_mode(&device_mode);

    return libspdm_tpm_append_mel_entry(
        measurement_extension_log, mel_entry, mel_buffer_size, measurements_index,
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM,
        &device_mode, sizeof(device_mode));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
#include "meas_config.h"
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if (LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP)
void libspdm_generate_mel(uint32_t measurement_hash_algo)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry;

    libspdm_zero_mem(m_libspdm_mel, sizeof(m_libspdm_mel));
    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                          sizeof(spdm_measurement_extension_log_dmtf_t));

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if (!libspdm_tpm_generate_measurement_extension_log(
            measurement_hash_algo, measurement_extension_log, &mel_entry,
            sizeof(m_libspdm_mel))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to generate TPM MEL\n"));
        libspdm_zero_mem(m_libspdm_mel, sizeof(m_libspdm_mel));
    }
#else
    (void)measurement_hash_algo;
    (void)mel_entry;
#endif
}
#endif /*(LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP) || (LIBSPDM_ENABLE_CAPABILITY_MEL_CAP)*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

bool g_check_measurement_request_context = false;
uint64_t g_measurement_request_context;

libspdm_return_t libspdm_measurement_collection(
    void *spdm_context,
    const uint32_t *session_id,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    uint8_t request_attribute,
    const uint8_t *requester_nonce,
    uint8_t slot_id_param,
    size_t request_context_size,
    const void *request_context,
    uint8_t *content_changed,
    uint8_t *measurements_count,
    void *measurements,
    size_t *measurements_size)
{
    size_t total_size_needed;
    bool use_bit_stream;
    size_t measurement_block_size;

    if ((measurement_specification != SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (g_check_measurement_request_context) {
        if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
            LIBSPDM_ASSERT(request_context_size == SPDM_REQ_CONTEXT_SIZE);
            LIBSPDM_ASSERT(libspdm_read_uint64(request_context) == g_measurement_request_context);
        } else {
            LIBSPDM_ASSERT(request_context_size == 0);
            LIBSPDM_ASSERT(request_context == NULL);
        }
    }

    LIBSPDM_ASSERT(libspdm_get_measurement_hash_size(measurement_hash_algo) != 0);

    use_bit_stream = false;
    if ((measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) ||
        ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED) !=
         0)) {
        use_bit_stream = true;
    }

    if (measurements_index ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        *measurements_count = LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER;
        goto successful_return;
    } else if (measurements_index ==
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        total_size_needed =
            libspdm_tpm_get_measurement_total_size(use_bit_stream, measurement_hash_algo);
        if ((LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER != 0) && (total_size_needed == 0)) {
            return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
        }

        LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
        if (total_size_needed > *measurements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *measurements_size = total_size_needed;
        *measurements_count = LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER;
        measurement_block_size = libspdm_tpm_fill_all_measurement_blocks(
            use_bit_stream, measurement_hash_algo, measurements);
        if ((LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER != 0) &&
            (measurement_block_size != total_size_needed)) {
            return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
        }

        goto successful_return;
    } else {
        if (!libspdm_tpm_is_measurement_index_configured(measurements_index)) {
            *measurements_count = 0;
            return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
        }

        total_size_needed = libspdm_tpm_fill_measurement_block(
            use_bit_stream, measurement_hash_algo, measurements_index, NULL);
        if (total_size_needed == 0) {
            return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
        }

        LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
        if (total_size_needed > *measurements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *measurements_count = 1;
        *measurements_size = total_size_needed;

        measurement_block_size = libspdm_tpm_fill_measurement_block(
            use_bit_stream, measurement_hash_algo, measurements_index, measurements);
        if (measurement_block_size == 0) {
            return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
        }
    }

successful_return:
    if ((content_changed != NULL) &&
        ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_12)) {
        /* return content change*/
        if ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
            0) {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED;
        } else {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

size_t libspdm_secret_lib_meas_opaque_data_size;

bool libspdm_measurement_opaque_data(
    void *spdm_context,
    const uint32_t *session_id,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    size_t request_context_size,
    const void *request_context,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_meas_opaque_data_size <= *opaque_data_size);

    if (g_check_measurement_request_context) {
        if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
            LIBSPDM_ASSERT(request_context_size == SPDM_REQ_CONTEXT_SIZE);
            LIBSPDM_ASSERT(libspdm_read_uint64(request_context) == g_measurement_request_context);
        } else {
            LIBSPDM_ASSERT(request_context_size == 0);
            LIBSPDM_ASSERT(request_context == NULL);
        }
    }

    *opaque_data_size = libspdm_secret_lib_meas_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}

#ifndef LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE
#define LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE 0x1000
#endif

bool libspdm_generate_measurement_summary_hash(
    void *spdm_context,
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash,
    uint32_t measurement_summary_hash_size)
{
    uint8_t measurement_data[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t index;
    spdm_measurement_block_dmtf_t *cached_measurement_block;
    size_t measurement_data_size;
    size_t measurement_block_size;
    uint8_t device_measurement[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t device_measurement_count;
    size_t device_measurement_size;
    libspdm_return_t status;
    bool result;

    switch (measurement_summary_hash_type) {
    case SPDM_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        return false;

    case SPDM_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_REQUEST_ALL_MEASUREMENTS_HASH:
        if (measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
            return false;
        }

        /* get all measurement data*/
        device_measurement_size = sizeof(device_measurement);
        status = libspdm_measurement_collection(
            spdm_context,
            NULL,
            spdm_version, measurement_specification,
            measurement_hash_algo,
            0xFF, /* Get all measurements*/
            0,
            NULL,
            0,
            0,
            NULL,
            NULL,
            &device_measurement_count, device_measurement,
            &device_measurement_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }

        /* double confirm that MeasurementData internal size is correct*/
        measurement_data_size = 0;
        cached_measurement_block = (void *)device_measurement;
        for (index = 0; index < device_measurement_count; index++) {
            measurement_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            LIBSPDM_ASSERT(cached_measurement_block
                           ->measurement_block_common_header
                           .measurement_size ==
                           sizeof(spdm_measurement_block_dmtf_header_t) +
                           cached_measurement_block
                           ->measurement_block_dmtf_header
                           .dmtf_spec_measurement_value_size);
            measurement_data_size +=
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            cached_measurement_block =
                (void *)((size_t)cached_measurement_block +
                         measurement_block_size);
        }

        LIBSPDM_ASSERT(measurement_data_size <=
                       LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE);

        /* get required data and hash them*/
        cached_measurement_block = (void *)device_measurement;
        measurement_data_size = 0;
        for (index = 0; index < device_measurement_count; index++) {
            measurement_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurement_block
                ->measurement_block_common_header
                .measurement_size;
            /* filter unneeded data*/
            if ((measurement_summary_hash_type ==
                 SPDM_REQUEST_ALL_MEASUREMENTS_HASH) ||
                ((cached_measurement_block
                  ->measurement_block_dmtf_header
                  .dmtf_spec_measurement_value_type &
                  SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) ==
                 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
                libspdm_copy_mem(&measurement_data[measurement_data_size],
                                 sizeof(measurement_data)
                                 - (&measurement_data[measurement_data_size] - measurement_data),
                                 cached_measurement_block,
                                 sizeof(cached_measurement_block->
                                        measurement_block_common_header) +
                                 cached_measurement_block->measurement_block_common_header
                                 .measurement_size);
                measurement_data_size +=
                    sizeof(cached_measurement_block->measurement_block_common_header) +
                    cached_measurement_block
                    ->measurement_block_common_header
                    .measurement_size;
            }
            cached_measurement_block =
                (void *)((size_t)cached_measurement_block +
                         measurement_block_size);
        }

        result = libspdm_hash_all(base_hash_algo, measurement_data,
                                  measurement_data_size, measurement_summary_hash);
        if (!result) {
            return false;
        }
        break;
    default:
        return false;
        break;
    }
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/*Collect the measurement extension log.*/
bool libspdm_measurement_extension_log_collection(
    void *spdm_context,
    uint8_t mel_specification,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    void **spdm_mel,
    size_t *spdm_mel_size)
{
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
        (mel_specification != SPDM_MEL_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return false;
    }

    libspdm_generate_mel(measurement_hash_algo);

    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    *spdm_mel = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;
    *spdm_mel_size = (size_t)(measurement_extension_log->mel_entries_len) +
                     sizeof(spdm_measurement_extension_log_dmtf_t);
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEL_CAP */
