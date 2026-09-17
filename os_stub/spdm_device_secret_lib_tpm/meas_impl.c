/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
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

#include <base.h>
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_common_lib.h"
#include "meas_impl.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

#include "meas_data.h"

extern uint8_t m_libspdm_mel[];
void libspdm_generate_mel(uint32_t measurement_hash_algo);

bool libspdm_tpm_get_svn(
    spdm_measurements_secure_version_number_t *svn)
{
#if LIBSPDM_TPM_SVN_NV_INDEX_ENABLED
    void *nv_data;
    size_t nv_data_size;

    nv_data = NULL;
    nv_data_size = 0;
    if (!libspdm_tpm_read_nv(LIBSPDM_TPM_SVN_NV_INDEX, &nv_data, &nv_data_size)) {
        return false;
    }

    if (nv_data_size < sizeof(*svn)) {
        free(nv_data);
        return false;
    }

    libspdm_copy_mem(svn, sizeof(*svn), nv_data, sizeof(*svn));
    free(nv_data);
    return true;
#else
    *svn = LIBSPDM_TPM_SVN_VALUE;
    return true;
#endif
}

void libspdm_tpm_get_device_mode(
    spdm_measurements_device_mode_t *device_mode)
{
    device_mode->operational_mode_capabilities =
        LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE_CAPABILITIES;
    device_mode->operational_mode_state =
        LIBSPDM_TPM_DEVICE_OPERATIONAL_MODE_STATE;
    device_mode->device_mode_capabilities =
        LIBSPDM_TPM_DEVICE_MODE_CAPABILITIES;
    device_mode->device_mode_state =
        LIBSPDM_TPM_DEVICE_MODE_STATE;
}

const void *libspdm_tpm_get_measurement_manifest(
    size_t *manifest_size)
{
    *manifest_size = sizeof(m_libspdm_tpm_measurement_manifest);
    return &m_libspdm_tpm_measurement_manifest;
}

/**
 * Fill PCR measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_pcr_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block)
{
    size_t hash_size;
    void *buffer;
    size_t buffer_size;

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    if (hash_size == 0) {
        return 0;
    }

    if (use_bit_stream) {
        if (measurement_block == NULL) {
            return sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_RAW_DATA_SIZE;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "use_bit_stream for PCR block for TPM device is not supported"));
        return 0;
    }

    if (measurements_index == 0) {
        return 0;
    }

    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
    }

    measurement_block->measurement_block_common_header.index = measurements_index;
    measurement_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        (measurements_index - 1);
    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)hash_size;

    measurement_block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)hash_size);

    buffer = (uint8_t *)(measurement_block + 1);
    buffer_size = hash_size;
    if (!libspdm_tpm_read_pcr(measurement_hash_algo, (uint32_t)(measurements_index - 1),
                              buffer, &buffer_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to read pcr from TPM"));
        return 0;
    }

    if (buffer_size != hash_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "hash_size (%d) != buffer_size (%d)\n",
                       (int)hash_size, (int)buffer_size));
        return 0;
    }

    return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
}

size_t libspdm_fill_measurement_image_hash_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block)
{
    return libspdm_fill_measurement_pcr_block(use_bit_stream, measurement_hash_algo,
                                              measurements_index, measurement_block);
}

/**
 * Fill SVN measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_svn_block(
    spdm_measurement_block_dmtf_t *measurement_block)
{
    spdm_measurements_secure_version_number_t svn;

    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + sizeof(svn);
    }

    if (!libspdm_tpm_get_svn(&svn)) {
        return 0;
    }

    measurement_block->measurement_block_common_header.index = LIBSPDM_MEASUREMENT_INDEX_SVN;
    measurement_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(svn);

    measurement_block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(svn));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(svn), (void *)&svn,
                     sizeof(svn));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(svn);
}

/**
 * Fill HEM measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_hem_block(
    spdm_measurement_block_dmtf_t *measurement_block,
    uint32_t measurement_hash_algo)
{
    size_t hash_size;
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry;
    uint32_t index;
    uint8_t *verify_hem;

    if (measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) {
        return 0;
    }

    libspdm_generate_mel(measurement_hash_algo);

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    if (hash_size == 0) {
        return 0;
    }
    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
    }

    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)m_libspdm_mel;

    measurement_block->measurement_block_common_header.index = LIBSPDM_MEASUREMENT_INDEX_HEM;
    measurement_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HASH_EXTEND_MEASUREMENT;
    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)hash_size;

    measurement_block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)hash_size);

    verify_hem = malloc(measurement_extension_log->mel_entries_len + hash_size);
    if (verify_hem == NULL) {
        return 0;
    }

    libspdm_zero_mem(verify_hem, measurement_extension_log->mel_entries_len + hash_size);
    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                          sizeof(spdm_measurement_extension_log_dmtf_t));
    for (index = 0; index < measurement_extension_log->number_of_entries; index++) {
        libspdm_copy_mem(
            verify_hem + hash_size,
            measurement_extension_log->mel_entries_len,
            mel_entry,
            sizeof(spdm_mel_entry_dmtf_t) +
            mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);

        if (!libspdm_measurement_hash_all(
                measurement_hash_algo,
                verify_hem,
                hash_size + sizeof(spdm_mel_entry_dmtf_t) +
                mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size,
                verify_hem)) {
            free(verify_hem);
            return 0;
        }
        mel_entry = (spdm_mel_entry_dmtf_t *)
                    ((uint8_t *)mel_entry + sizeof(spdm_mel_entry_dmtf_t) +
                     mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
    }

    libspdm_copy_mem((void *)(measurement_block + 1), hash_size, verify_hem, hash_size);
    free(verify_hem);
    return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
}

/**
 * Fill manifest measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_manifest_block(
    spdm_measurement_block_dmtf_t *measurement_block)
{
    const void *manifest;
    size_t manifest_size;

    manifest = libspdm_tpm_get_measurement_manifest(&manifest_size);

    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + manifest_size;
    }

    measurement_block->measurement_block_common_header.index =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST;
    measurement_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)manifest_size;

    measurement_block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)manifest_size);

    libspdm_copy_mem((void *)(measurement_block + 1), manifest_size,
                     manifest, manifest_size);

    return sizeof(spdm_measurement_block_dmtf_t) + manifest_size;
}

/**
 * Fill device mode measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_measurement_device_mode_block(
    spdm_measurement_block_dmtf_t *measurement_block)
{
    spdm_measurements_device_mode_t device_mode;

    libspdm_tpm_get_device_mode(&device_mode);

    if (measurement_block == NULL) {
        return sizeof(spdm_measurement_block_dmtf_t) + sizeof(device_mode);
    }

    measurement_block->measurement_block_common_header.index =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE;
    measurement_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
    measurement_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)sizeof(device_mode);

    measurement_block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                   (uint16_t)sizeof(device_mode));

    libspdm_copy_mem((void *)(measurement_block + 1), sizeof(device_mode),
                     (void *)&device_mode, sizeof(device_mode));

    return sizeof(spdm_measurement_block_dmtf_t) + sizeof(device_mode);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */
