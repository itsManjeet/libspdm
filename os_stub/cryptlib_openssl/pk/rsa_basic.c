/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide basic capabilities for RSA:
 * 1) libspdm_rsa_new
 * 2) libspdm_rsa_free
 * 3) libspdm_rsa_set_key
 * 4) rsa_pkcs1_verify
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "rsa_context.h"

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, libspdm_rsa_new() returns NULL.
 *
 **/
void *libspdm_rsa_new(void)
{
    libspdm_rsa_ctx_evp_t *ctx;

    ctx = (libspdm_rsa_ctx_evp_t *)allocate_pool(sizeof(libspdm_rsa_ctx_evp_t));
    if (ctx == NULL) {
        return NULL;
    }
    libspdm_zero_mem(ctx, sizeof(*ctx));
    ctx->pkey = NULL;
    return (void *)ctx;
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void libspdm_rsa_free(void *rsa_context)
{
    libspdm_rsa_ctx_evp_t *ctx;

    if (rsa_context == NULL) {
        return;
    }
    ctx = (libspdm_rsa_ctx_evp_t *)rsa_context;
    EVP_PKEY_free(ctx->pkey);
    libspdm_rsa_ctx_free_bns(ctx);
    free_pool(ctx);
}

/**
 * Sets the tag-designated key component into the established RSA context.
 *
 * This function sets the tag-designated RSA key component into the established
 * RSA context from the user-specified non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If big_number is NULL, then the specified key component in RSA context is cleared.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[in]       big_number   Pointer to octet integer buffer.
 *                             If NULL, then the specified key component in RSA
 *                             context is cleared.
 * @param[in]       bn_size      size of big number buffer in bytes.
 *                             If big_number is NULL, then it is ignored.
 *
 * @retval  true   RSA key component was set successfully.
 * @retval  false  Invalid RSA key component tag.
 *
 **/
bool libspdm_rsa_set_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         const uint8_t *big_number, size_t bn_size)
{
    libspdm_rsa_ctx_evp_t *ctx;
    BIGNUM *bn_new;

    if (rsa_context == NULL || bn_size > INT_MAX) {
        return false;
    }
    ctx = (libspdm_rsa_ctx_evp_t *)rsa_context;

    /* Handle clear operation */
    if (big_number == NULL) {
        switch (key_tag) {
        case LIBSPDM_RSA_KEY_N:
            BN_free(ctx->bn_n); ctx->bn_n = NULL; break;
        case LIBSPDM_RSA_KEY_E:
            BN_free(ctx->bn_e); ctx->bn_e = NULL; break;
        case LIBSPDM_RSA_KEY_D:
            BN_free(ctx->bn_d); ctx->bn_d = NULL; break;
        case LIBSPDM_RSA_KEY_P:
            BN_free(ctx->bn_p); ctx->bn_p = NULL; break;
        case LIBSPDM_RSA_KEY_Q:
            BN_free(ctx->bn_q); ctx->bn_q = NULL; break;
        case LIBSPDM_RSA_KEY_DP:
            BN_free(ctx->bn_dp); ctx->bn_dp = NULL; break;
        case LIBSPDM_RSA_KEY_DQ:
            BN_free(ctx->bn_dq); ctx->bn_dq = NULL; break;
        case LIBSPDM_RSA_KEY_Q_INV:
            BN_free(ctx->bn_q_inv); ctx->bn_q_inv = NULL; break;
        default:
            return false;
        }
        libspdm_rsa_ctx_try_build_pkey(ctx);
        return true;
    }

    bn_new = BN_bin2bn(big_number, (uint32_t)bn_size, NULL);
    if (bn_new == NULL) {
        return false;
    }

    switch (key_tag) {
    case LIBSPDM_RSA_KEY_N:
        BN_free(ctx->bn_n); ctx->bn_n = bn_new; break;
    case LIBSPDM_RSA_KEY_E:
        BN_free(ctx->bn_e); ctx->bn_e = bn_new; break;
    case LIBSPDM_RSA_KEY_D:
        BN_free(ctx->bn_d); ctx->bn_d = bn_new; break;
    case LIBSPDM_RSA_KEY_P:
        BN_free(ctx->bn_p); ctx->bn_p = bn_new; break;
    case LIBSPDM_RSA_KEY_Q:
        BN_free(ctx->bn_q); ctx->bn_q = bn_new; break;
    case LIBSPDM_RSA_KEY_DP:
        BN_free(ctx->bn_dp); ctx->bn_dp = bn_new; break;
    case LIBSPDM_RSA_KEY_DQ:
        BN_free(ctx->bn_dq); ctx->bn_dq = bn_new; break;
    case LIBSPDM_RSA_KEY_Q_INV:
        BN_free(ctx->bn_q_inv); ctx->bn_q_inv = bn_new; break;
    default:
        BN_free(bn_new);
        return false;
    }

    libspdm_rsa_ctx_try_build_pkey(ctx);
    return true;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in PKCS1-v1_5.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pkcs1_verify_with_nid(void *rsa_context, size_t hash_nid,
                                       const uint8_t *message_hash,
                                       size_t hash_size, const uint8_t *signature,
                                       size_t sig_size)
{
    EVP_MD *evp_md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc;
    bool result = false;
    libspdm_rsa_ctx_evp_t *ctx = (libspdm_rsa_ctx_evp_t *)rsa_context;

    /* Check input parameters.*/

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    if (ctx == NULL || ctx->pkey == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA512", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-512", NULL);
        break;

    default:
        return false;
    }

    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->pkey, NULL);
    if (pctx == NULL) {
        EVP_MD_free(evp_md);
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_verify_init_ex(pctx, params);
        if (rc != 1) {
            EVP_MD_free(evp_md);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_signature_md(pctx, (const EVP_MD *)evp_md);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    if (rc == 1) {
        result = true;
    }

    EVP_MD_free(evp_md);
    EVP_PKEY_CTX_free(pctx);
    return result;
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify(void *rsa_context, size_t hash_nid,
                            const uint8_t *message_hash, size_t hash_size,
                            const uint8_t *signature, size_t sig_size)
{
    EVP_MD *evp_md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc;
    bool result = false;
    libspdm_rsa_ctx_evp_t *ctx = (libspdm_rsa_ctx_evp_t *)rsa_context;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    if (ctx == NULL || ctx->pkey == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA512", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-512", NULL);
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    if (evp_md == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->pkey, NULL);
    if (pctx == NULL) {
        EVP_MD_free(evp_md);
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_verify_init_ex(pctx, params);
        if (rc != 1) {
            EVP_MD_free(evp_md);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_signature_md(pctx, (const EVP_MD *)evp_md);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, (const EVP_MD *)evp_md);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    if (rc == 1) {
        result = true;
    }

    EVP_MD_free(evp_md);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

#if LIBSPDM_FIPS_MODE
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify_fips(void *rsa_context, size_t hash_nid,
                                 const uint8_t *message_hash, size_t hash_size,
                                 const uint8_t *signature, size_t sig_size)
{
    EVP_MD *evp_md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int rc;
    bool result = false;
    libspdm_rsa_ctx_evp_t *ctx = (libspdm_rsa_ctx_evp_t *)rsa_context;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    if (ctx == NULL || ctx->pkey == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA512", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-384", NULL);
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        evp_md = EVP_MD_fetch(NULL, "SHA3-512", NULL);
        break;

    default:
        return false;
    }

    if (evp_md == NULL) {
        return false;
    }

    if (ctx == NULL || ctx->pkey == NULL) {
        return false;
    }

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, ctx->pkey, NULL);
    if (pctx == NULL) {
        return false;
    }

    {
        OSSL_PARAM params[2];
        const char *md_name = EVP_MD_get0_name(evp_md);
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md_name, 0);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_verify_init_ex(pctx, params);
        if (rc != 1) {
            EVP_MD_free(evp_md);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_signature_md(pctx, (const EVP_MD *)evp_md);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, (const EVP_MD *)evp_md);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    /* salt len is 0 for FIPS test */
    rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0);
    if (rc != 1) {
        EVP_MD_free(evp_md);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    rc = EVP_PKEY_verify(pctx, signature, sig_size, message_hash, hash_size);
    if (rc == 1) {
        result = true;
    }

    EVP_MD_free(evp_md);
    EVP_PKEY_CTX_free(pctx);
    return result;
}
#endif /*LIBSPDM_FIPS_MODE*/

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
