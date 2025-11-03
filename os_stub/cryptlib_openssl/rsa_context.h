/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Context Structure and Helper Functions.
 **/

#ifndef __RSA_CONTEXT_H__
#define __RSA_CONTEXT_H__

#include "internal_crypt_lib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

/**
 * RSA context structure using EVP_PKEY with cached BIGNUM components.
 **/
typedef struct {
    EVP_PKEY *pkey;
    BIGNUM *bn_n;
    BIGNUM *bn_e;
    BIGNUM *bn_d;
    BIGNUM *bn_p;
    BIGNUM *bn_q;
    BIGNUM *bn_dp;
    BIGNUM *bn_dq;
    BIGNUM *bn_q_inv;
} libspdm_rsa_ctx_evp_t;

/**
 * Free all cached BIGNUM components in RSA context.
 *
 * @param[in]  ctx  Pointer to RSA context.
 **/
void libspdm_rsa_ctx_free_bns(libspdm_rsa_ctx_evp_t *ctx);

/**
 * Try to build EVP_PKEY from cached BIGNUM components.
 *
 * @param[in, out]  ctx  Pointer to RSA context.
 **/
void libspdm_rsa_ctx_try_build_pkey(libspdm_rsa_ctx_evp_t *ctx);

/**
 * Export BIGNUM components from EVP_PKEY to cache if cache is empty.
 *
 * @param[in, out]  ctx  Pointer to RSA context.
 **/
void libspdm_evp_export_to_cache(libspdm_rsa_ctx_evp_t *ctx);

#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#endif /* __RSA_CONTEXT_H__ */
