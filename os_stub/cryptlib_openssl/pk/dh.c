/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Diffie-Hellman Wrapper Implementation over.
 *
 * RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>

#if LIBSPDM_FFDHE_SUPPORT

/* Define generator constants */
#define LIBSPDM_DH_GENERATOR_2 2
#define LIBSPDM_DH_GENERATOR_5 5

/**
 * Allocates and Initializes one Diffie-Hellman context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 *         If the allocations fails, dh_new() returns NULL.
 *
 **/
void *libspdm_dh_new_by_nid(size_t nid)
{
    EVP_PKEY_CTX *param_ctx = NULL;
    EVP_PKEY *params = NULL;
    const char *group_name = NULL;

    /* Map libspdm NID to OpenSSL group name */
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_FFDHE2048:
        group_name = "ffdhe2048";
        break;
    case LIBSPDM_CRYPTO_NID_FFDHE3072:
        group_name = "ffdhe3072";
        break;
    case LIBSPDM_CRYPTO_NID_FFDHE4096:
        group_name = "ffdhe4096";
        break;
    default:
        return NULL;
    }

    /* Create a context for the DH algorithm */
    param_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!param_ctx) {
        return NULL;
    }

    /* Initialize for parameter generation */
    if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        return NULL;
    }

    /* Set the named group using OSSL_PARAM */
    OSSL_PARAM params_set[2];
    params_set[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     (char *)group_name, 0);
    params_set[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(param_ctx, params_set) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        return NULL;
    }

    /* Generate parameters (which in this case, sets the named group) */
    if (EVP_PKEY_paramgen(param_ctx, &params) <= 0) {
        EVP_PKEY_CTX_free(param_ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(param_ctx);

    /* Return double pointer to ensure context can be updated */
    EVP_PKEY **dh_context_ptr = malloc(sizeof(EVP_PKEY *));
    if (dh_context_ptr == NULL) {
        EVP_PKEY_free(params);
        return NULL;
    }
    *dh_context_ptr = params;
    return dh_context_ptr;
}

/**
 * Release the specified DH context.
 *
 * If dh_context is NULL, then return false.
 *
 * @param[in]  dh_context  Pointer to the DH context to be released.
 *
 **/
void libspdm_dh_free(void *dh_context)
{
    if (dh_context != NULL) {
        EVP_PKEY **pkey_ptr = (EVP_PKEY **)dh_context;
        if (*pkey_ptr != NULL) {
            EVP_PKEY_free(*pkey_ptr);
        }
        free(pkey_ptr);
    }
}

/**
 * Generates DH parameter.
 *
 * Given generator g, and length of prime number p in bits, this function generates p,
 * and sets DH context according to value of g and p.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator    value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[out]      prime        Pointer to the buffer to receive the generated prime number.
 *
 * @retval true   DH parameter generation succeeded.
 * @retval false  value of generator is not supported.
 * @retval false  PRNG fails to generate random prime number with prime_length.
 *
 **/
bool libspdm_dh_generate_parameter(void *dh_context, size_t generator,
                                   size_t prime_length, uint8_t *prime)
{
    EVP_PKEY_CTX *param_ctx = NULL;
    EVP_PKEY *params = NULL;
    BIGNUM *bn_p = NULL;
    bool ret_val = false;

    /* Check input parameters.*/
    if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
        return false;
    }

    if (generator != LIBSPDM_DH_GENERATOR_2 && generator != LIBSPDM_DH_GENERATOR_5) {
        return false;
    }

    /* Create a context for parameter generation */
    param_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!param_ctx) {
        return false;
    }

    if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
        goto cleanup;
    }

    /* Set the prime length */
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(param_ctx, (int)prime_length) <= 0) {
        goto cleanup;
    }

    /* Set the generator */
    if (EVP_PKEY_CTX_set_dh_paramgen_generator(param_ctx, (int)generator) <= 0) {
        goto cleanup;
    }

    /* Generate parameters */
    if (EVP_PKEY_paramgen(param_ctx, &params) <= 0) {
        goto cleanup;
    }

    /* Extract the prime p */
    if (EVP_PKEY_get_bn_param(params, OSSL_PKEY_PARAM_FFC_P, &bn_p) <= 0) {
        goto cleanup;
    }

    /* Convert the prime to binary */
    int p_size = BN_bn2bin(bn_p, prime);
    if (p_size <= 0) {
        goto cleanup;
    }

    /* Update the context */
    EVP_PKEY **ctx_ptr = (EVP_PKEY **)dh_context;
    EVP_PKEY_free(*ctx_ptr);
    *ctx_ptr = params;
    params = NULL; /* Avoid double-free */

    ret_val = true;

cleanup:
    EVP_PKEY_CTX_free(param_ctx);
    EVP_PKEY_free(params);
    BN_free(bn_p);
    return ret_val;
}

/**
 * Sets generator and prime parameters for DH.
 *
 * Given generator g, and prime number p, this function and sets DH
 * context accordingly.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator    value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[in]       prime        Pointer to the prime number.
 *
 * @retval true   DH parameter setting succeeded.
 * @retval false  value of generator is not supported.
 * @retval false  value of generator is not suitable for the prime.
 * @retval false  value of prime is not a prime number.
 * @retval false  value of prime is not a safe prime number.
 *
 **/
bool libspdm_dh_set_parameter(void *dh_context, size_t generator,
                              size_t prime_length, const uint8_t *prime)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *ossl_params = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_g = NULL;
    bool result = false;

    /* Check input parameters.*/
    if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
        return false;
    }

    if (generator != LIBSPDM_DH_GENERATOR_2 && generator != LIBSPDM_DH_GENERATOR_5) {
        return false;
    }

    /* Convert prime and generator to BIGNUM */
    bn_p = BN_bin2bn(prime, (int)(prime_length / 8), NULL);
    bn_g = BN_new();
    if (!bn_p || !bn_g || !BN_set_word(bn_g, generator)) {
        goto cleanup;
    }

    /* Build parameters using OSSL_PARAM_BLD */
    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, bn_g)) {
        goto cleanup;
    }

    ossl_params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!ossl_params) {
        goto cleanup;
    }

    /* Create DH parameters from the built OSSL_PARAM array */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!ctx) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(ctx, &params, EVP_PKEY_KEY_PARAMETERS, ossl_params) <= 0) {
        goto cleanup;
    }

    /* Update the context */
    EVP_PKEY **ctx_ptr = (EVP_PKEY **)dh_context;
    EVP_PKEY_free(*ctx_ptr);
    *ctx_ptr = params;
    params = NULL;

    result = true;

cleanup:
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(ossl_params);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(params);
    BN_free(bn_p);
    BN_free(bn_g);
    return result;
}

/**
 * Generates DH public key.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * If dh_context is NULL, then return false.
 * If public_key_size is NULL, then return false.
 * If public_key_size is large enough but public_key is NULL, then return false.
 *
 * For FFDHE2048, the public_size is 256.
 * For FFDHE3072, the public_size is 384.
 * For FFDHE4096, the public_size is 512.
 *
 * @param[in, out]  dh_context      Pointer to the DH context.
 * @param[out]      public_key      Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
 *                                On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DH public key generation succeeded.
 * @retval false  DH public key generation failed.
 * @retval false  public_key_size is not large enough.
 *
 **/
bool libspdm_dh_generate_key(void *dh_context, uint8_t *public_key,
                             size_t *public_key_size)
{
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *keypair = NULL;
    BIGNUM *pub_key = NULL;
    size_t final_pub_key_size;
    int size;
    bool ret_val = false;

    /* Check input parameters */
    if (dh_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    EVP_PKEY **ctx_ptr = (EVP_PKEY **)dh_context;
    EVP_PKEY *original_key = *ctx_ptr;
    if (original_key == NULL) {
        return false;
    }

    /* Determine the expected public key size based on the DH parameters */
    int key_size = EVP_PKEY_get_size(original_key);
    switch (key_size) {
    case 256:
        final_pub_key_size = 256;
        break;
    case 384:
        final_pub_key_size = 384;
        break;
    case 512:
        final_pub_key_size = 512;
        break;
    default:
        return false;
    }

    if (*public_key_size < final_pub_key_size) {
        *public_key_size = final_pub_key_size;
        return false;
    }

    /* Generate key pair from parameters */
    key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, original_key, NULL);
    if (!key_ctx) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_keygen(key_ctx, &keypair) <= 0) {
        goto cleanup;
    }

    /* Extract the public key in BN form */
    if (EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) <= 0) {
        goto cleanup;
    }

    size = BN_num_bytes(pub_key);
    if (size <= 0 || (size_t)size > final_pub_key_size) {
        goto cleanup;
    }

    if (public_key != NULL) {
        libspdm_zero_mem(public_key, *public_key_size);
        /* Store public key in big-endian format */
        BN_bn2bin(pub_key, &public_key[final_pub_key_size - size]);
    }

    /* Replace the context with the new key pair */
    EVP_PKEY_free(original_key);
    *ctx_ptr = keypair;
    keypair = NULL; /* Ownership transferred */

    *public_key_size = final_pub_key_size;
    ret_val = true;

cleanup:
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(keypair);
    BN_free(pub_key);
    return ret_val;
}

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * If dh_context is NULL, then return false.
 * If peer_public_key is NULL, then return false.
 * If key_size is NULL, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 *
 * For FFDHE2048, the peer_public_size and key_size is 256.
 * For FFDHE3072, the peer_public_size and key_size is 384.
 * For FFDHE4096, the peer_public_size and key_size is 512.
 *
 * @param[in, out]  dh_context          Pointer to the DH context.
 * @param[in]       peer_public_key      Pointer to the peer's public key.
 * @param[in]       peer_public_key_size  size of peer's public key in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                    On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DH exchanged key generation succeeded.
 * @retval false  DH exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
bool libspdm_dh_compute_key(void *dh_context, const uint8_t *peer_public_key,
                            size_t peer_public_key_size, uint8_t *key,
                            size_t *key_size)
{
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY *peer_pkey = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *ossl_params = NULL;
    EVP_PKEY_CTX *peer_ctx = NULL;
    BIGNUM *peer_pub_key = NULL;
    BIGNUM *p = NULL, *g = NULL;
    size_t secret_len = 0;
    size_t final_key_size;
    bool result = false;

    /* Check input parameters.*/
    if (dh_context == NULL || peer_public_key == NULL || key_size == NULL ||
        key == NULL) {
        return false;
    }

    if (peer_public_key_size > INT_MAX) {
        return false;
    }

    EVP_PKEY **ctx_ptr = (EVP_PKEY **)dh_context;
    EVP_PKEY *dh_key = *ctx_ptr;
    if (dh_key == NULL) {
        return false;
    }

    /* Determine the expected key size based on the DH parameters */
    int dh_size = EVP_PKEY_get_size(dh_key);
    switch (dh_size) {
    case 256:
        final_key_size = 256;
        break;
    case 384:
        final_key_size = 384;
        break;
    case 512:
        final_key_size = 512;
        break;
    default:
        return false;
    }

    if (*key_size < final_key_size) {
        *key_size = final_key_size;
        return false;
    }

    /* Convert peer's public key to BIGNUM */
    peer_pub_key = BN_bin2bn(peer_public_key, (int)peer_public_key_size, NULL);
    if (!peer_pub_key) {
        return false;
    }

    /* Build parameters for the peer's public key */
    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        goto cleanup;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, peer_pub_key)) {
        goto cleanup;
    }

    /* We also need to set the same DH parameters (p, g) for the peer's key */
    if (EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_FFC_P, &p) > 0 &&
        EVP_PKEY_get_bn_param(dh_key, OSSL_PKEY_PARAM_FFC_G, &g) > 0) {
        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p);
        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g);
    } else {
        goto cleanup;
    }

    ossl_params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!ossl_params) {
        goto cleanup;
    }

    /* Create a temporary EVP_PKEY for the peer's public key */
    peer_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!peer_ctx) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata_init(peer_ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_fromdata(peer_ctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, ossl_params) <= 0) {
        goto cleanup;
    }

    /* Perform key derivation */
    derive_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_key, NULL);
    if (!derive_ctx) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_init_ex(derive_ctx, NULL) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pkey) <= 0) {
        goto cleanup;
    }

    /* Get the length of the shared secret */
    if (EVP_PKEY_derive(derive_ctx, NULL, &secret_len) <= 0) {
        goto cleanup;
    }

    if (secret_len != final_key_size) {
        goto cleanup;
    }

    /* Perform the derivation and get the shared secret */
    if (EVP_PKEY_derive(derive_ctx, key, &secret_len) <= 0) {
        goto cleanup;
    }

    *key_size = secret_len;
    result = true;

cleanup:
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_CTX_free(peer_ctx);
    EVP_PKEY_free(peer_pkey);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(ossl_params);
    BN_free(peer_pub_key);
    BN_free(p);
    BN_free(g);
    return result;
}

#endif /* LIBSPDM_FFDHE_SUPPORT */
