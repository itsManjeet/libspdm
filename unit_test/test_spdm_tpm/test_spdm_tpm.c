/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/responder/measlib.h"
#include "industry_standard/spdm_secured_message.h"
#include "keys.h"
#include "meas_impl.h"
#include "meas_data.h"
#include <tss2/tss2_mu.h>

extern size_t libspdm_secret_lib_meas_opaque_data_size;

extern size_t libspdm_fill_measurement_image_hash_block(
    bool use_bit_stream,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    spdm_measurement_block_dmtf_t *measurement_block);

static bool is_tpm_available(void)
{
    return (getenv("TPM2TOOLS_TCTI") != NULL);
}

/* --------------------------------------------------------------------------
 * Offline / Parameter Validation & Invariant Tests
 * -------------------------------------------------------------------------- */

static void test_tpm_device_init(void **state)
{
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_tpm_device_init();
    assert_true(status);

    /* Test idempotency */
    status = libspdm_tpm_device_init();
    assert_true(status);
}

static void test_tpm_key_handle_null_params(void **state)
{
    void *context = NULL;
    bool status;

    status = libspdm_tpm_get_pvt_key_handle(NULL, &context);
    assert_false(status);
    assert_null(context);

    status = libspdm_tpm_get_pvt_key_handle("handle:0x81000021", NULL);
    assert_false(status);

    status = libspdm_tpm_get_pub_key_handle(NULL, &context);
    assert_false(status);
    assert_null(context);

    status = libspdm_tpm_get_pub_key_handle("handle:0x81000021", NULL);
    assert_false(status);
}

static void test_tpm_read_pcr_validation(void **state)
{
    uint8_t buffer[64];
    size_t size;
    bool status;

    size = sizeof(buffer);

    /* NULL buffer */
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, NULL, &size);
    assert_false(status);

    /* NULL size */
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, NULL);
    assert_false(status);

    /* Unsupported algorithm */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(0xFFFFFFFF, 0, buffer, &size);
    assert_false(status);

    /* Invalid index (>= 24) */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 24, buffer, &size);
    assert_false(status);

    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 100, buffer, &size);
    assert_false(status);

    /* Buffer undersize check: should return required size (32 for SHA256) */
    size = 16;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, &size);
    assert_false(status);
    assert_int_equal(size, 32);

    /* Buffer undersize check: SHA384 requires 48 bytes */
    size = 16;
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, 0, buffer, &size);
    assert_false(status);
    assert_int_equal(size, 48);
}

static void test_tpm_read_nv_validation(void **state)
{
    void *buffer = NULL;
    size_t size = 0;
    bool status;

    status = libspdm_tpm_read_nv(0x1500021, NULL, &size);
    assert_false(status);

    status = libspdm_tpm_read_nv(0x1500021, &buffer, NULL);
    assert_false(status);
    assert_null(buffer);
}

static void test_spdm_tpm_security_stubs(void **state)
{
    void *data = NULL;
    size_t size = 0;
    void *context = NULL;
    bool status;

    /* Raw private keys must never be readable from the TPM stub */
    status = libspdm_read_responder_private_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_get_responder_private_key_from_raw_data(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &context);
    assert_false(status);

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
    status = libspdm_read_requester_private_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_get_requester_private_key_from_raw_data(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &context);
    assert_false(status);
#endif

    status = libspdm_read_responder_public_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);

    status = libspdm_read_requester_public_key(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, &data, &size);
    assert_false(status);
}

static void test_spdm_tpm_meas_validation(void **state)
{
    spdm_measurement_block_dmtf_t block;
    size_t block_size;

    /* use_bit_stream is not supported for TPM */
    block_size = libspdm_fill_measurement_image_hash_block(
        true, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, &block);
    assert_int_equal(block_size, 0);

    /* measurements_index 0 is invalid */
    block_size = libspdm_fill_measurement_image_hash_block(
        false, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, &block);
    assert_int_equal(block_size, 0);
}

static void test_spdm_tpm_mel_uses_configured_measurements(void **state)
{
    void *mel;
    size_t mel_size;
    spdm_measurement_extension_log_dmtf_t *measurement_extension_log;
    spdm_mel_entry_dmtf_t *mel_entry;
    uint32_t index;
    bool status;
    bool has_svn;
    bool has_manifest;
    bool has_device_mode;

    mel = NULL;
    mel_size = 0;
    has_svn = false;
    has_manifest = false;
    has_device_mode = false;

    status = libspdm_measurement_extension_log_collection(
        NULL,
        SPDM_MEL_SPECIFICATION_DMTF,
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
        &mel,
        &mel_size);
    assert_true(status);
    assert_non_null(mel);
    assert_true(mel_size >= sizeof(spdm_measurement_extension_log_dmtf_t));

    measurement_extension_log = (spdm_measurement_extension_log_dmtf_t *)mel;
    assert_int_equal(mel_size,
                     sizeof(spdm_measurement_extension_log_dmtf_t) +
                     measurement_extension_log->mel_entries_len);

    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)measurement_extension_log +
                                          sizeof(spdm_measurement_extension_log_dmtf_t));
    for (index = 0; index < measurement_extension_log->number_of_entries; index++) {
        uint8_t measurement_type;

        measurement_type =
            mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_type &
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK;

        assert_int_not_equal(measurement_type,
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL);
        assert_int_not_equal(measurement_type,
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION);
        assert_int_not_equal(mel_entry->meas_index, LIBSPDM_MEASUREMENT_INDEX_HEM);

        if (mel_entry->meas_index == LIBSPDM_MEASUREMENT_INDEX_SVN) {
            assert_int_equal(measurement_type,
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER);
            has_svn = true;
        } else if (mel_entry->meas_index ==
                   SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_MEASUREMENT_MANIFEST) {
            const libspdm_tpm_measurement_manifest_header_t *manifest_header;
            const libspdm_tpm_measurement_manifest_entry_t *manifest_entry;

            assert_int_equal(measurement_type,
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST);
            assert_int_equal(
                mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size,
                sizeof(libspdm_tpm_measurement_manifest_t));

            manifest_header = (const libspdm_tpm_measurement_manifest_header_t *)(mel_entry + 1);
            assert_int_equal(manifest_header->version, 1);
            assert_int_equal(manifest_header->size, sizeof(libspdm_tpm_measurement_manifest_t));
            assert_int_equal(manifest_header->vendor_id, 0);
            assert_int_equal(manifest_header->measurement_count,
                             LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER);
            assert_int_equal(manifest_header->flags, 0);
            assert_int_equal(manifest_header->reserved, 0);

            manifest_entry =
                (const libspdm_tpm_measurement_manifest_entry_t *)(manifest_header + 1);
            assert_int_equal(manifest_entry[0].index, 0x1);
            assert_int_equal(manifest_entry[0].kind, LIBSPDM_TPM_MEASUREMENT_KIND_PCR);
            has_manifest = true;
        } else if (mel_entry->meas_index ==
                   SPDM_MEASUREMENT_BLOCK_MEASUREMENT_INDEX_DEVICE_MODE) {
            const spdm_measurements_device_mode_t *device_mode;

            assert_int_equal(measurement_type,
                             SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE);
            assert_int_equal(
                mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size,
                sizeof(spdm_measurements_device_mode_t));

            device_mode = (const spdm_measurements_device_mode_t *)(mel_entry + 1);
            assert_int_equal(device_mode->operational_mode_capabilities,
                             SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE);
            assert_int_equal(device_mode->operational_mode_state,
                             SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE);
            assert_int_equal(device_mode->device_mode_capabilities, 0);
            assert_int_equal(device_mode->device_mode_state, 0);
            has_device_mode = true;
        }

        mel_entry = (spdm_mel_entry_dmtf_t *)
                    ((uint8_t *)mel_entry + sizeof(spdm_mel_entry_dmtf_t) +
                     mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
    }

    assert_true(has_svn);
    assert_true(has_manifest);
    assert_true(has_device_mode);
}

static void test_spdm_tpm_cert_slot_validation(void **state)
{
    void *data = NULL;
    size_t size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    bool status;

    /* Unsupported slot (slot 7 is not in default 0;1;4 mask) */
    status = libspdm_read_responder_root_public_certificate_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    status = libspdm_read_responder_public_certificate_chain_per_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    /* Out of range slot (>= SPDM_MAX_SLOT_COUNT) */
    status = libspdm_read_responder_root_public_certificate_slot(
        8, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);

    /* Algorithm 0 is invalid */
    status = libspdm_read_responder_certificate(0, &data, &size);
    assert_false(status);

    /* PQC responder root certificate slot test with invalid slot */
    status = libspdm_read_pqc_responder_root_public_certificate_slot(
        7, SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &data, &size, &hash, &hash_size);
    assert_false(status);
}

void test_spdm_tpm_quote_validation(void **state)
{
    uint8_t buffer[512];
    size_t size = sizeof(buffer);
    bool status;

    /* libspdm_tpm_quote with NULL quote_buffer_size */
    status = libspdm_tpm_quote(
        LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        NULL, 0, NULL, 0, buffer, NULL);
    assert_false(status);

    /* libspdm_tpm_quote with invalid hash algorithm */
    size = sizeof(buffer);
    status = libspdm_tpm_quote(
        LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0,
        0xFFFFFFFF, NULL, 0, NULL, 0, buffer, &size);
    assert_false(status);

    /* libspdm_tpm_quote with invalid key handle string */
    size = sizeof(buffer);
    status = libspdm_tpm_quote(
        "invalid_handle",
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        NULL, 0, NULL, 0, buffer, &size);
    assert_false(status);

    /* libspdm_tpm_verify_quote with NULL parameters */
    status = libspdm_tpm_verify_quote(
        NULL,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        buffer, sizeof(buffer), NULL, 0);
    assert_false(status);

    status = libspdm_tpm_verify_quote(
        (void *)1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        NULL, sizeof(buffer), NULL, 0);
    assert_false(status);

    status = libspdm_tpm_verify_quote(
        (void *)1,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        buffer, 0, NULL, 0);
    assert_false(status);
}

static void test_spdm_tpm_quote_rejects_invalid_selection(void **state)
{
    uint8_t buffer[2048];
    size_t size = sizeof(buffer);
    uint8_t pcrs[] = {0, 24};
    const uint32_t bank = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    const char *key = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0;

    assert_false(libspdm_tpm_quote(key, bank, pcrs, 2, NULL, 0, buffer, &size));
    pcrs[1] = 0;
    assert_false(libspdm_tpm_quote(key, bank, pcrs, 2, NULL, 0, buffer, &size));
    assert_false(libspdm_tpm_quote(key, bank, NULL, 0, NULL, 0, buffer, &size));
    assert_false(libspdm_tpm_quote(key, bank, pcrs, 1, NULL, 32, buffer, &size));
    assert_false(libspdm_tpm_quote(key, bank, pcrs, 1, buffer, sizeof(buffer), buffer, &size));
    assert_false(libspdm_tpm_quote("handle:0x81000021junk", bank, pcrs, 1,
                                 NULL, 0, buffer, &size));
}

/* --------------------------------------------------------------------------
 * Live TPM Simulator Tests (gated by TPM2TOOLS_TCTI)
 * -------------------------------------------------------------------------- */

static void test_tpm_live_read_pcr(void **state)
{
    uint8_t buffer[64];
    size_t size;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 0, buffer, &size);
    assert_true(status);
    assert_int_equal(size, 32);

    /* Read PCR 1 */
    size = sizeof(buffer);
    status = libspdm_tpm_read_pcr(
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, buffer, &size);
    assert_true(status);
    assert_int_equal(size, 32);
}

static void test_tpm_live_read_nv(void **state)
{
    void *buffer = NULL;
    size_t size = 0;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_tpm_read_nv(
        LIBSPDM_TPM_HANDLE_RESPONDER_CERTCHAIN_SLOT_0, &buffer, &size);
    assert_true(status);
    assert_non_null(buffer);
    assert_true(size > 0);

    free(buffer);
}

static void test_spdm_tpm_live_read_certchain(void **state)
{
    void *cert_chain = NULL;
    size_t cert_chain_size = 0;
    void *hash = NULL;
    size_t hash_size = 0;
    spdm_cert_chain_t *chain_header;
    bool status;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    status = libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > sizeof(spdm_cert_chain_t));
    assert_non_null(hash);
    assert_int_equal(hash_size, 32);

    chain_header = (spdm_cert_chain_t *)cert_chain;
    assert_int_equal(chain_header->length, (uint32_t)cert_chain_size);

    free(cert_chain);

    /* Test root public certificate extraction */
    status = libspdm_read_responder_root_public_certificate(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > 0);
    free(cert_chain);

    /* Test leaf certificate extraction */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size);
    assert_true(status);
    assert_non_null(cert_chain);
    assert_true(cert_chain_size > 0);
    free(cert_chain);

    /* Test PQC wrapper calls responder cert */
    status = libspdm_read_pqc_responder_root_public_certificate(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_chain, &cert_chain_size, &hash, &hash_size);
    assert_true(status);
    assert_non_null(cert_chain);
    free(cert_chain);
}

static void test_spdm_tpm_live_fill_meas_block(void **state)
{
    uint8_t buffer[512];
    spdm_measurement_block_dmtf_t *block;
    size_t block_size;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    block = (spdm_measurement_block_dmtf_t *)buffer;
    block_size = libspdm_fill_measurement_image_hash_block(
        false, SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, 1, block);

    assert_true(block_size > 0);
    assert_int_equal(block->measurement_block_common_header.index, 1);
    assert_int_equal(block->measurement_block_common_header.measurement_specification,
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    assert_int_equal(block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size, 32);
    assert_int_equal(block_size, sizeof(spdm_measurement_block_dmtf_t) + 32);
}

static void test_spdm_tpm_live_sign_and_verify(void **state)
{
    uint8_t digest[32];
    uint8_t signature[128];
    size_t sig_size = sizeof(signature);
    void *cert_data = NULL;
    size_t cert_size = 0;
    void *context = NULL;
    bool status;
    size_t i;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    /* Prepare a test digest */
    for (i = 0; i < sizeof(digest); i++) {
        digest[i] = (uint8_t)(i + 1);
    }

    /* Perform TPM signature */
    status = libspdm_responder_data_sign(
        NULL, SPDM_MESSAGE_VERSION_12, 0, 0,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, 0,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, true,
        digest, sizeof(digest), signature, &sig_size);
    assert_true(status);
    assert_true(sig_size > 0);

    /* Read the leaf certificate from NV to verify the signature */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_data, &cert_size);
    assert_true(status);
    assert_non_null(cert_data);

    /* Extract public key and verify signature */
    status = libspdm_asym_get_public_key_from_x509(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        cert_data, cert_size, &context);
    assert_true(status);
    assert_non_null(context);

    status = libspdm_asym_verify_hash(
        SPDM_MESSAGE_VERSION_12, 0,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
        context, digest, sizeof(digest), signature, sig_size);
    assert_true(status);

    libspdm_asym_free(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, context);
    free(cert_data);
}

void test_spdm_tpm_live_quote(void **state)
{
    uint8_t quote_buf[1024];
    size_t quote_size = sizeof(quote_buf);
    uint8_t pcr_indices[] = {0, 1};
    uint8_t nonce[32];
    uint8_t bad_nonce[32];
    void *cert_data = NULL;
    size_t cert_size = 0;
    void *pub_key_ctx = NULL;
    bool status;
    size_t i;

    if (!is_tpm_available()) {
        print_message("[SKIPPED] TPM simulator not running (TPM2TOOLS_TCTI not set)\n");
        return;
    }

    for (i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)(0xA0 + i);
        bad_nonce[i] = (uint8_t)(0xB0 + i);
    }

    /* Perform TPM2 quote directly */
    status = libspdm_tpm_quote(
        LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        pcr_indices, 2,
        nonce, sizeof(nonce),
        quote_buf, &quote_size);
    assert_true(status);
    assert_true(quote_size > 0);

    /* Read responder certificate to obtain public key */
    status = libspdm_read_responder_certificate(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        &cert_data, &cert_size);
    assert_true(status);
    assert_non_null(cert_data);

    status = libspdm_asym_get_public_key_from_x509(
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        cert_data, cert_size, &pub_key_ctx);
    assert_true(status);
    assert_non_null(pub_key_ctx);

    /* Verify quote with matching nonce */
    status = libspdm_tpm_verify_quote(
        pub_key_ctx,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        quote_buf, quote_size,
        nonce, sizeof(nonce));
    assert_true(status);

    /* Verification must fail with wrong nonce */
    status = libspdm_tpm_verify_quote(
        pub_key_ctx,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        quote_buf, quote_size,
        bad_nonce, sizeof(bad_nonce));
    assert_false(status);

    /* Verification must fail with tampered quote buffer */
    quote_buf[quote_size - 1] ^= 0xFF;
    status = libspdm_tpm_verify_quote(
        pub_key_ctx,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        quote_buf, quote_size,
        nonce, sizeof(nonce));
    assert_false(status);

    libspdm_asym_free(SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, pub_key_ctx);
    free(cert_data);
}

/* --------------------------------------------------------------------------
 * Main Test Runner
 * -------------------------------------------------------------------------- */

#if LIBSPDM_TPM_MEASUREMENT_QUOTE
static void test_spdm_tpm_live_measurement_quote(void **state)
{
    libspdm_context_t *context;
    spdm_get_measurements_request_t request = {0};
    uint8_t opaque[2048];
    uint8_t measurement[128];
    uint8_t pcr_values[24 * 32];
    uint32_t pcr_mask = 0;
    size_t pcr_values_size = 0;
    size_t digest_size;
    uint8_t count;
    size_t opaque_size;
    size_t measurement_size = sizeof(measurement);
    size_t index;
    uint8_t measurement_index = 0;
    void *cert = NULL;
    size_t cert_size = 0;
    void *public_key = NULL;
    const uint32_t bank = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
    const uint32_t asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
    const spdm_version_number_t version = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    if (!is_tpm_available()) {
        skip();
    }
    for (index = 0; index < LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER; index++) {
        if (m_libspdm_tpm_measurement_manifest.entries[index].kind ==
            LIBSPDM_TPM_MEASUREMENT_KIND_PCR) {
            measurement_index = m_libspdm_tpm_measurement_manifest.entries[index].index;
            break;
        }
    }
    if (measurement_index == 0) {
        skip();
    }
    context = calloc(1, sizeof(*context));
    assert_non_null(context);
    context->connection_info.algorithm.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    request.header.param2 = measurement_index;
    memset(request.nonce, 0xA5, sizeof(request.nonce));
    context->last_spdm_request = &request;
    context->last_spdm_request_size = sizeof(request);
    assert_int_equal(libspdm_measurement_collection(context, NULL, version,
                     SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, measurement_index,
                     request.header.param1, request.nonce, 0, 0, NULL, NULL,
                     &count, measurement, &measurement_size), LIBSPDM_STATUS_SUCCESS);
    opaque_size = sizeof(opaque);
    assert_true(libspdm_measurement_opaque_data(context, NULL, version,
                SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, measurement_index,
                request.header.param1, 0, NULL, opaque, &opaque_size));
    assert_true(opaque_size > 8);
    assert_true(libspdm_read_responder_certificate(asym, &cert, &cert_size));
    assert_true(libspdm_asym_get_public_key_from_x509(asym, cert, cert_size, &public_key));
    assert_true(libspdm_tpm_verify_quote(public_key, asym, bank, opaque, opaque_size,
                                        request.nonce, sizeof(request.nonce)));
    /* Short buffers report a required size without writing past the capacity. */
    opaque_size = 1;
    opaque[0] = 0xCC;
    assert_false(libspdm_measurement_opaque_data(context, NULL, version,
                 SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, measurement_index,
                 request.header.param1, 0, NULL, opaque, &opaque_size));
    assert_true(opaque_size > 1);
    assert_int_equal(opaque[0], 0xCC);
    /* The all-measurements selection contains every configured PCR only. */
    for (index = 0; index < LIBSPDM_TPM_MEASUREMENT_BLOCK_NUMBER; index++) {
        if (m_libspdm_tpm_measurement_manifest.entries[index].kind ==
            LIBSPDM_TPM_MEASUREMENT_KIND_PCR) {
            pcr_mask |= 1u << (m_libspdm_tpm_measurement_manifest.entries[index].index - 1);
        }
    }
    for (index = 0; index < 24; index++) {
        if ((pcr_mask & (1u << index)) != 0) {
            digest_size = 32;
            assert_true(libspdm_tpm_read_pcr(bank, (uint32_t)index,
                        pcr_values + pcr_values_size, &digest_size));
            pcr_values_size += digest_size;
        }
    }
    request.header.param2 = 0xFF;
    opaque_size = sizeof(opaque);
    assert_true(libspdm_measurement_opaque_data(context, NULL, version,
                SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, 0xFF,
                request.header.param1, 0, NULL, opaque, &opaque_size));
    assert_true(libspdm_tpm_verify_quote(public_key, asym, bank, opaque, opaque_size,
                                        request.nonce, sizeof(request.nonce)));
    /* Unsigned and count-only callbacks carry no quote. */
    opaque_size = sizeof(opaque);
    assert_true(libspdm_measurement_opaque_data(NULL, NULL, version,
                SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, measurement_index,
                0, 0, NULL, opaque, &opaque_size));
    assert_int_equal(opaque_size, 0);
    opaque_size = sizeof(opaque);
    assert_true(libspdm_measurement_opaque_data(context, NULL, version,
                SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, 0,
                request.header.param1, 0, NULL, opaque, &opaque_size));
    assert_int_equal(opaque_size, 0);
    request.header.param2 = measurement_index;
    request.slot_id_param = 0xF;
    opaque_size = sizeof(opaque);
    assert_false(libspdm_measurement_opaque_data(context, NULL, version,
                 SPDM_MEASUREMENT_SPECIFICATION_DMTF, bank, measurement_index,
                 request.header.param1, 0, NULL, opaque, &opaque_size));
    libspdm_asym_free(asym, public_key);
    free(cert);
    free(context);
}
#endif

static int libspdm_spdm_tpm_test_main(void)
{
    const struct CMUnitTest test_cases[] = {
        /* Offline tests */
        cmocka_unit_test(test_tpm_device_init),
        cmocka_unit_test(test_tpm_key_handle_null_params),
        cmocka_unit_test(test_tpm_read_pcr_validation),
        cmocka_unit_test(test_tpm_read_nv_validation),
        cmocka_unit_test(test_spdm_tpm_security_stubs),
        cmocka_unit_test(test_spdm_tpm_meas_validation),
        cmocka_unit_test(test_spdm_tpm_mel_uses_configured_measurements),
        cmocka_unit_test(test_spdm_tpm_cert_slot_validation),
        cmocka_unit_test(test_spdm_tpm_quote_validation),
        cmocka_unit_test(test_spdm_tpm_quote_rejects_invalid_selection),

        /* Live TPM tests */
        cmocka_unit_test(test_tpm_live_read_pcr),
        cmocka_unit_test(test_tpm_live_read_nv),
        cmocka_unit_test(test_spdm_tpm_live_read_certchain),
        cmocka_unit_test(test_spdm_tpm_live_fill_meas_block),
        cmocka_unit_test(test_spdm_tpm_live_sign_and_verify),
        cmocka_unit_test(test_spdm_tpm_live_quote),
#if LIBSPDM_TPM_MEASUREMENT_QUOTE
        cmocka_unit_test(test_spdm_tpm_live_measurement_quote),
#endif
    };

    return cmocka_run_group_tests(test_cases, NULL, NULL);
}


int main(void)
{
    return libspdm_spdm_tpm_test_main();
}
