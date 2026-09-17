/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef LIBSPDM_TPM_MEAS_IMPL_H
#define LIBSPDM_TPM_MEAS_IMPL_H

#define LIBSPDM_TPM_MEASUREMENT_KIND_PCR 1
#define LIBSPDM_TPM_MEASUREMENT_KIND_SVN 2
#define LIBSPDM_TPM_MEASUREMENT_KIND_HEM 3
#define LIBSPDM_TPM_MEASUREMENT_KIND_MANIFEST 4
#define LIBSPDM_TPM_MEASUREMENT_KIND_DEVICE_MODE 5

#pragma pack(1)
typedef struct {
    uint8_t version;
    uint16_t size;
    uint16_t vendor_id;
    uint8_t measurement_count;
    uint8_t flags;
    uint16_t reserved;
} libspdm_tpm_measurement_manifest_header_t;

typedef struct {
    uint8_t index;
    uint8_t kind;
    uint16_t flags;
} libspdm_tpm_measurement_manifest_entry_t;
#pragma pack()

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

bool libspdm_tpm_get_svn(
    spdm_measurements_secure_version_number_t *svn);

void libspdm_tpm_get_device_mode(
    spdm_measurements_device_mode_t *device_mode);

const void *libspdm_tpm_get_measurement_manifest(
    size_t *manifest_size);

size_t libspdm_fill_measurement_pcr_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block);

size_t libspdm_fill_measurement_image_hash_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block);

size_t libspdm_fill_measurement_svn_block(
    spdm_measurement_block_dmtf_t *measurement_block);

size_t libspdm_fill_measurement_hem_block(
    spdm_measurement_block_dmtf_t *measurement_block,
    uint32_t measurement_hash_algo);

size_t libspdm_fill_measurement_manifest_block(
    spdm_measurement_block_dmtf_t *measurement_block);

size_t libspdm_fill_measurement_device_mode_block(
    spdm_measurement_block_dmtf_t *measurement_block);

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#endif /* LIBSPDM_TPM_MEAS_IMPL_H */
