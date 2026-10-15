/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <openssl/err.h>
#include <errno.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_crypt_lib.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_secured_message.h"

#include "../key_context.h"

bool g_tpm_device_initialized = false;

static libspdm_key_context *create_key_context(EVP_PKEY *pkey)
{
    libspdm_key_context *context;

    if (pkey == NULL) {
        return NULL;
    }

    context = (libspdm_key_context *)malloc(sizeof(libspdm_key_context));
    if (context == NULL) {
        return NULL;
    }
    context->evp_pkey = pkey;
    return context;
}

bool libspdm_tpm_device_init()
{
    OSSL_PROVIDER *tpm_provider = NULL;

    if (g_tpm_device_initialized)
        return true;

    tpm_provider = OSSL_PROVIDER_load(NULL, "tpm2");
    if (tpm_provider == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "failed to load tpm2\n"));
        return false;
    }

    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    g_tpm_device_initialized = true;
    return true;
}

static bool get_keyinfo(const char *handle, void **context, int keyinfo_type)
{
    OSSL_STORE_CTX *store_ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    if (handle == NULL || context == NULL) {
        return false;
    }
    *context = NULL;

    /* handle must look like: "handle:0x81010002" or "tpm2tss:0x81010002" */
    store_ctx = OSSL_STORE_open_ex(handle, NULL, "provider=tpm2", NULL, NULL, NULL, NULL, NULL);
    if (!store_ctx){
        return false;
    }

    while ((info = OSSL_STORE_load(store_ctx)) != NULL)
    {
        if (OSSL_STORE_INFO_get_type(info) == keyinfo_type){
            switch (keyinfo_type)
            {
            case OSSL_STORE_INFO_PKEY:
                *context = OSSL_STORE_INFO_get1_PKEY(info);
                break;
            case OSSL_STORE_INFO_PUBKEY:
                *context = OSSL_STORE_INFO_get1_PUBKEY(info);
                break;
            case OSSL_STORE_INFO_CERT:
                *context = OSSL_STORE_INFO_get1_CERT(info);
                break;
            }
            OSSL_STORE_INFO_free(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    OSSL_STORE_close(store_ctx);

    if (*context == NULL){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "no keyinfo %d found on handle %s\n", keyinfo_type, handle));
        return false;
    }

    return true;
}

bool libspdm_tpm_get_pvt_key_handle(const void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;

    if (context == NULL) {
        return false;
    }
    *context = NULL;

    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    if (*context == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    return true;
}

bool libspdm_tpm_get_pub_key_handle(const void *handle, void **context)
{
    EVP_PKEY *pkey = NULL;

    if (context == NULL) {
        return false;
    }
    *context = NULL;

    if (!get_keyinfo((const char *)handle, (void **)&pkey, OSSL_STORE_INFO_PUBKEY)){
        return false;
    }
    *context = create_key_context(pkey);
    if (*context == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }
    return true;
}

static bool map_spdm_meas_hash_to_tpm(uint32_t meas_hash_algo, TPMI_ALG_HASH *tpm_hash)
{
    switch (meas_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
        *tpm_hash = TPM2_ALG_SHA3_256;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
        *tpm_hash = TPM2_ALG_SHA256;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
        *tpm_hash = TPM2_ALG_SHA3_384;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
        *tpm_hash = TPM2_ALG_SHA384;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
        *tpm_hash = TPM2_ALG_SHA3_512;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
        *tpm_hash = TPM2_ALG_SHA512;
        return true;
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
        *tpm_hash = TPM2_ALG_SM3_256;
        return true;
    default:
        return false;
    }
}

bool libspdm_tpm_read_pcr(uint32_t hash_algo, uint32_t index, void *buffer, size_t *size)
{
    TSS2_RC result = 1;
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    ESYS_CONTEXT *context = NULL;
    TPML_PCR_SELECTION *out = NULL;
    TPML_DIGEST *values = NULL;
    size_t digest_size = 0;
    UINT32 uc;

    TPML_PCR_SELECTION sel = {
        .count = 1,
        .pcrSelections = {
            {
                .sizeofSelect = 3,
                .pcrSelect = {0x00, 0x00, 0x00, 0x00},
            },
        }
    };

    if (buffer == NULL || size == NULL) {
        return false;
    }

    if (index >= 24) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "invalid PCR index %u (max 23)\n", index));
        return false;
    }

    if (!map_spdm_meas_hash_to_tpm(hash_algo, &sel.pcrSelections[0].hash)) {
        return false;
    }
    digest_size = libspdm_get_measurement_hash_size(hash_algo);
    if (digest_size == 0) {
        return false;
    }

    if (*size < digest_size) {
        *size = digest_size;
        return false;
    }

    sel.pcrSelections[0].pcrSelect[index / 8] |= (uint8_t)(1 << (index % 8));

    const char *tssconf = getenv("TPM2TOOLS_TCTI");
    if ((result = Tss2_TctiLdr_Initialize(tssconf, &tcti_context)) != TSS2_RC_SUCCESS){
        goto finish;
    }

    /* TODO: abi version check */
    if ((result = Esys_Initialize(&context, tcti_context, NULL)) != TSS2_RC_SUCCESS){
        goto cleanup_tcti;
    }

    if ((result = Esys_PCR_Read(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &sel, &uc, &out,
                                &values)) != TSS2_RC_SUCCESS){
        goto cleanup_esys;
    }

    if (values == NULL || values->count == 0 || values->digests[0].size < digest_size) {
        result = 1;
        goto cleanup_esys;
    }

    memcpy(buffer, values->digests[0].buffer, digest_size);
    *size = digest_size;

cleanup_esys:
    if (out != NULL) {
        Esys_Free(out);
    }
    if (values != NULL) {
        Esys_Free(values);
    }
    Esys_Finalize(&context);

cleanup_tcti:
    Tss2_TctiLdr_Finalize(&tcti_context);

finish:
    return result == TSS2_RC_SUCCESS;
}

bool libspdm_tpm_read_nv(uint32_t index, void **buffer, size_t *size)
{
    TSS2_RC rc = 1;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR nv_tr = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nv_pub = NULL;
    TPM2B_NAME *nv_name = NULL;
    TPMS_CAPABILITY_DATA *cap = NULL;

    UINT16 nv_size;
    UINT32 max_nv_buf;
    UINT16 offset = 0;

    if (buffer == NULL || size == NULL) {
        return false;
    }

    *buffer = NULL;
    *size = 0;

    rc = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_TR_FromTPMPublic(
        esys,
        index, /* TPM handle */
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_tr);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    rc = Esys_NV_ReadPublic(
        esys,
        nv_tr,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nv_pub,
        &nv_name);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    nv_size = nv_pub->nvPublic.dataSize;
    if (nv_size == 0) {
        rc = 1;
        goto out;
    }

    rc = Esys_GetCapability(
        esys,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_NV_BUFFER_MAX,
        1,
        NULL,
        &cap);
    if (rc != TSS2_RC_SUCCESS)
        goto out;

    if (cap != NULL && cap->data.tpmProperties.count > 0 &&
        cap->data.tpmProperties.tpmProperty[0].value > 0) {
        max_nv_buf = cap->data.tpmProperties.tpmProperty[0].value;
    } else {
        max_nv_buf = 1024;
    }

    *buffer = malloc(nv_size);
    if (!*buffer) {
        rc = 1;
        goto out;
    }

    while (offset < nv_size)
    {
        TPM2B_MAX_NV_BUFFER *chunk = NULL;
        UINT16 to_read = (nv_size - offset > max_nv_buf)
                             ? max_nv_buf
                             : nv_size - offset;

        rc = Esys_NV_Read(
            esys,
            nv_tr,
            nv_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            to_read,
            offset,
            &chunk);
        if (rc != TSS2_RC_SUCCESS){
            Esys_Free(chunk);
            goto out;
        }

        if (chunk == NULL || chunk->size == 0) {
            rc = 1;
            Esys_Free(chunk);
            goto out;
        }

        memcpy((uint8_t *)(*buffer) + offset,
               chunk->buffer,
               chunk->size);

        offset += chunk->size;
        Esys_Free(chunk);
    }

    *size = nv_size;
    rc = TSS2_RC_SUCCESS;

out:
    if (rc != TSS2_RC_SUCCESS && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
        *size = 0;
    }
    if (cap)
        Esys_Free(cap);
    if (nv_pub)
        Esys_Free(nv_pub);
    if (nv_name)
        Esys_Free(nv_name);
    if (nv_tr != ESYS_TR_NONE)
        Esys_TR_Close(esys, &nv_tr);
    if (esys)
        Esys_Finalize(&esys);
    if (tcti)
        Tss2_TctiLdr_Finalize(&tcti);

    return rc == TSS2_RC_SUCCESS;
}

static uint32_t parse_tpm_key_handle(const void *handle_param)
{
    const char *text;
    char *end;
    unsigned long handle;

    if (handle_param == NULL) {
        return 0;
    }
    if ((uintptr_t)handle_param >= 0x80000000u &&
        (uintptr_t)handle_param <= 0x81FFFFFFu) {
        return (uint32_t)(uintptr_t)handle_param;
    }
    text = handle_param;
    if (strncmp(text, "handle:", 7) == 0) {
        text += 7;
    } else if (strncmp(text, "tpm2tss:", 8) == 0) {
        text += 8;
    }
    if (*text == '-' || *text == '+' || *text == ' ' || *text == '\t') {
        return 0;
    }
    errno = 0;
    handle = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' ||
        handle < 0x80000000u || handle > 0x81FFFFFFu) {
        return 0;
    }
    return (uint32_t)handle;
}

bool libspdm_tpm_quote(
    const void *key_handle_str,
    uint32_t hash_algo,
    const uint8_t *pcr_indices,
    size_t pcr_count,
    const uint8_t *nonce,
    size_t nonce_size,
    void *quote_buffer,
    size_t *quote_buffer_size)
{
    TSS2_RC rc = 1;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;
    ESYS_TR key_tr = ESYS_TR_NONE;
    TPM2B_ATTEST *quoted = NULL;
    TPMT_SIGNATURE *signature = NULL;
    TPM2B_PUBLIC *key_public = NULL;
    uint32_t key_handle;
    TPMI_ALG_HASH tpm_hash;
    TPML_PCR_SELECTION pcr_selection;
    TPM2B_DATA qual_data;
    TPMT_SIG_SCHEME in_scheme;
    size_t required_size = 0;
    size_t offset = 0;
    size_t i;

    if (quote_buffer_size == NULL) {
        return false;
    }

    if (!map_spdm_meas_hash_to_tpm(hash_algo, &tpm_hash)) {
        return false;
    }

    key_handle = parse_tpm_key_handle(key_handle_str);
    if (key_handle == 0) {
        return false;
    }

    memset(&pcr_selection, 0, sizeof(pcr_selection));
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = tpm_hash;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;
    if ((pcr_indices == NULL) || (pcr_count == 0) || (pcr_count > 24) ||
        ((nonce == NULL) && (nonce_size != 0)) ||
        (nonce_size > sizeof(qual_data.buffer))) {
        return false;
    }
    for (i = 0; i < pcr_count; i++) {
        if ((pcr_indices[i] >= 24) ||
            ((pcr_selection.pcrSelections[0].pcrSelect[pcr_indices[i] / 8] &
              (1u << (pcr_indices[i] % 8))) != 0)) {
            return false;
        }
        pcr_selection.pcrSelections[0].pcrSelect[pcr_indices[i] / 8] |=
            (uint8_t)(1u << (pcr_indices[i] % 8));
    }
    memset(&qual_data, 0, sizeof(qual_data));
    qual_data.size = (UINT16)nonce_size;
    if (nonce_size != 0) {
        memcpy(qual_data.buffer, nonce, nonce_size);
    }
    memset(&in_scheme, 0, sizeof(in_scheme));
    in_scheme.scheme = TPM2_ALG_NULL;

    rc = Tss2_TctiLdr_Initialize(getenv("TPM2TOOLS_TCTI"), &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_TR_FromTPMPublic(esys, key_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &key_tr);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    rc = Esys_ReadPublic(esys, key_tr, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &key_public, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    if (key_public->publicArea.type == TPM2_ALG_ECC) {
        if (key_public->publicArea.parameters.eccDetail.scheme.scheme == TPM2_ALG_NULL) {
            in_scheme.scheme = TPM2_ALG_ECDSA;
            in_scheme.details.ecdsa.hashAlg = key_public->publicArea.nameAlg;
        }
    } else if (key_public->publicArea.type == TPM2_ALG_RSA) {
        if (key_public->publicArea.parameters.rsaDetail.scheme.scheme == TPM2_ALG_NULL) {
            in_scheme.scheme = TPM2_ALG_RSASSA;
            in_scheme.details.rsassa.hashAlg = key_public->publicArea.nameAlg;
        }
    } else {
        rc = 1;
        goto out;
    }

    rc = Esys_Quote(
        esys,
        key_tr,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &qual_data,
        &in_scheme,
        &pcr_selection,
        &quoted,
        &signature);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    /* Compute total required size */
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, NULL, 0, &required_size);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, NULL, 0, &required_size);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    if (quote_buffer == NULL || *quote_buffer_size < required_size) {
        *quote_buffer_size = required_size;
        rc = 1; /* Buffer insufficient or size query */
        goto out;
    }

    offset = 0;
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(quoted, (uint8_t *)quote_buffer, *quote_buffer_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, (uint8_t *)quote_buffer, *quote_buffer_size, &offset);
    if (rc != TSS2_RC_SUCCESS) {
        goto out;
    }

    *quote_buffer_size = offset;
    rc = TSS2_RC_SUCCESS;

out:
    Esys_Free(key_public);
    if (quoted != NULL) {
        Esys_Free(quoted);
    }
    if (signature != NULL) {
        Esys_Free(signature);
    }
    if (key_tr != ESYS_TR_NONE) {
        Esys_TR_Close(esys, &key_tr);
    }
    if (esys != NULL) {
        Esys_Finalize(&esys);
    }
    if (tcti != NULL) {
        Tss2_TctiLdr_Finalize(&tcti);
    }

    return (rc == TSS2_RC_SUCCESS);
}

static uint32_t map_tpm_hash_to_base_hash(TPMI_ALG_HASH tpm_hash)
{
    switch (tpm_hash) {
    case TPM2_ALG_SHA256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    case TPM2_ALG_SHA3_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256;
    case TPM2_ALG_SHA384:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    case TPM2_ALG_SHA3_384:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384;
    case TPM2_ALG_SHA512:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
    case TPM2_ALG_SHA3_512:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    case TPM2_ALG_SM3_256:
        return SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    default:
        return 0;
    }
}

static bool libspdm_tpm_unwrap_quote(const uint8_t **buffer, size_t *size)
{
    const uint8_t *raw_buf = *buffer;
    size_t raw_size = *size;
    /* Accept our single-element format 1 table, with strict bounds/padding. */
    if (raw_size >= 8 && raw_buf[0] == 1 && raw_buf[1] == 0 &&
        raw_buf[2] == 0 && raw_buf[3] == 0) {
        size_t payload_size = (size_t)raw_buf[6] | ((size_t)raw_buf[7] << 8);
        size_t padded_size = (8 + payload_size + 3) & ~(size_t)3;
        size_t padding_index;
        if (raw_buf[4] != SPDM_REGISTRY_ID_TCG || raw_buf[5] != 0 ||
            padded_size != raw_size || payload_size > raw_size - 8) {
            return false;
        }
        for (padding_index = 8 + payload_size; padding_index < raw_size; padding_index++) {
            if (raw_buf[padding_index] != 0) {
                return false;
            }
        }
        raw_buf += 8;
        raw_size = payload_size;
    }

    *buffer = raw_buf;
    *size = raw_size;
    return true;
}

bool libspdm_tpm_verify_quote(
    const void *pub_key_context,
    uint32_t base_asym_algo,
    uint32_t hash_algo,
    const void *quote_buffer,
    size_t quote_buffer_size,
    const uint8_t *expected_nonce,
    size_t expected_nonce_size)
{
    TSS2_RC rc;
    TPM2B_ATTEST attest;
    TPMS_ATTEST tpms_attest;
    TPMT_SIGNATURE sig;
    size_t offset = 0;
    size_t attest_offset = 0;
    uint8_t hash_digest[64];
    size_t hash_size = 0;
    uint8_t raw_sig[132];
    size_t component_size;

    if (pub_key_context == NULL || quote_buffer == NULL || quote_buffer_size == 0 ||
        (expected_nonce == NULL && expected_nonce_size != 0)) {
        return false;
    }

    const uint8_t *raw_buf = (const uint8_t *)quote_buffer;
    size_t raw_size = quote_buffer_size;

    if (!libspdm_tpm_unwrap_quote(&raw_buf, &raw_size)) {
        return false;
    }

    /* Unmarshal TPM2B_ATTEST */
    rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(raw_buf, raw_size, &offset, &attest);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    /* Unmarshal TPMT_SIGNATURE */
    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(raw_buf, raw_size, &offset, &sig);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    if (offset != raw_size) {
        return false;
    }

    /* Parse inner TPMS_ATTEST to check magic, type, and nonce */
    rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest.attestationData, attest.size, &attest_offset, &tpms_attest);
    if (rc != TSS2_RC_SUCCESS) {
        return false;
    }

    if (attest_offset != attest.size) {
        return false;
    }
    if (tpms_attest.magic != TPM2_GENERATED_VALUE) {
        return false;
    }
    if (tpms_attest.type != TPM2_ST_ATTEST_QUOTE) {
        return false;
    }

    if (tpms_attest.extraData.size != expected_nonce_size ||
        (expected_nonce_size != 0 &&
         memcmp(tpms_attest.extraData.buffer, expected_nonce, expected_nonce_size) != 0)) {
        return false;
    }

    TPMI_ALG_HASH tpm_sig_hash = TPM2_ALG_NULL;
    if (sig.sigAlg == TPM2_ALG_ECDSA) {
        tpm_sig_hash = sig.signature.ecdsa.hash;
    } else if (sig.sigAlg == TPM2_ALG_RSASSA) {
        tpm_sig_hash = sig.signature.rsassa.hash;
    } else if (sig.sigAlg == TPM2_ALG_RSAPSS) {
        tpm_sig_hash = sig.signature.rsapss.hash;
    } else {
        return false;
    }

    /* hash_algo identifies the PCR bank, independently of the key's scheme. */
    if (hash_algo != 0) {
        TPMI_ALG_HASH expected_tpm_hash;
        if (!map_spdm_meas_hash_to_tpm(hash_algo, &expected_tpm_hash) ||
            tpms_attest.attested.quote.pcrSelect.count != 1 ||
            tpms_attest.attested.quote.pcrSelect.pcrSelections[0].hash != expected_tpm_hash) {
            return false;
        }
    }

    uint32_t base_hash = map_tpm_hash_to_base_hash(tpm_sig_hash);
    if (base_hash == 0) {
        return false;
    }

    hash_size = libspdm_get_hash_size(base_hash);
    if (hash_size == 0 || hash_size > sizeof(hash_digest)) {
        return false;
    }

    if (!libspdm_hash_all(base_hash, attest.attestationData, attest.size, hash_digest)) {
        return false;
    }

    /* Extract signature according to algorithm.
     * Use spdm_version=0 so libspdm_asym_verify_hash verifies raw message_hash
     * directly without prepending the SPDM 1.2 signing context prefix. */
    if (sig.sigAlg == TPM2_ALG_ECDSA) {
        component_size = libspdm_get_asym_signature_size(base_asym_algo) / 2;
        if ((base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 &&
             base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 &&
             base_asym_algo != SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521) ||
            component_size == 0 || component_size > sizeof(raw_sig) / 2 ||
            sig.signature.ecdsa.signatureR.size == 0 ||
            sig.signature.ecdsa.signatureS.size == 0 ||
            sig.signature.ecdsa.signatureR.size > component_size ||
            sig.signature.ecdsa.signatureS.size > component_size) {
            return false;
        }
        memset(raw_sig, 0, sizeof(raw_sig));
        memcpy(raw_sig + component_size - sig.signature.ecdsa.signatureR.size,
               sig.signature.ecdsa.signatureR.buffer, sig.signature.ecdsa.signatureR.size);
        memcpy(raw_sig + 2 * component_size - sig.signature.ecdsa.signatureS.size,
               sig.signature.ecdsa.signatureS.buffer, sig.signature.ecdsa.signatureS.size);

        return libspdm_asym_verify_hash(
            0, 0,
            base_asym_algo, base_hash,
            (void *)pub_key_context,
            hash_digest, hash_size,
            raw_sig, 2 * component_size);
    } else if (sig.sigAlg == TPM2_ALG_RSASSA || sig.sigAlg == TPM2_ALG_RSAPSS) {
        return libspdm_asym_verify_hash(
            0, 0,
            base_asym_algo, base_hash,
            (void *)pub_key_context,
            hash_digest, hash_size,
            sig.signature.rsassa.sig.buffer,
            sig.signature.rsassa.sig.size);
    }

    return false;
}
