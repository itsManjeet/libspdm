/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Context Helper Functions Implementation.
 **/

#include "internal_crypt_lib.h"
#include "rsa_context.h"

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

void libspdm_rsa_ctx_free_bns(libspdm_rsa_ctx_evp_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BN_free(ctx->bn_n);
    BN_free(ctx->bn_e);
    BN_free(ctx->bn_d);
    BN_free(ctx->bn_p);
    BN_free(ctx->bn_q);
    BN_free(ctx->bn_dp);
    BN_free(ctx->bn_dq);
    BN_free(ctx->bn_q_inv);
    ctx->bn_n = NULL;
    ctx->bn_e = NULL;
    ctx->bn_d = NULL;
    ctx->bn_p = NULL;
    ctx->bn_q = NULL;
    ctx->bn_dp = NULL;
    ctx->bn_dq = NULL;
    ctx->bn_q_inv = NULL;
}

void libspdm_rsa_ctx_try_build_pkey(libspdm_rsa_ctx_evp_t *ctx)
{
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params;
    EVP_PKEY_CTX *pkctx;
    EVP_PKEY *new_pkey;
    int is_public_only;

    if (ctx == NULL) {
        return;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        return;
    }
    if (ctx->bn_n != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, ctx->bn_n)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_e != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, ctx->bn_e)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_d != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, ctx->bn_d)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_p != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, ctx->bn_p)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_q != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, ctx->bn_q)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_dp != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, ctx->bn_dp)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_dq != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, ctx->bn_dq)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }
    if (ctx->bn_q_inv != NULL) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, ctx->bn_q_inv)) {
            OSSL_PARAM_BLD_free(bld);
            return;
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (params == NULL) {
        return;
    }

    pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (pkctx == NULL) {
        OSSL_PARAM_free(params);
        return;
    }
    if (EVP_PKEY_fromdata_init(pkctx) != 1) {
        EVP_PKEY_CTX_free(pkctx);
        OSSL_PARAM_free(params);
        return;
    }

    /* First try building a full keypair if private parts exist, else public key. */
    is_public_only = (ctx->bn_d == NULL) && (ctx->bn_p == NULL) && (ctx->bn_q == NULL) &&
                     (ctx->bn_dp == NULL) && (ctx->bn_dq == NULL) && (ctx->bn_q_inv == NULL);

    new_pkey = NULL;
    if (!is_public_only) {
        if (EVP_PKEY_fromdata(pkctx, &new_pkey, EVP_PKEY_KEYPAIR, params) != 1) {
            /* fall through to try public if that fails */
            new_pkey = NULL;
        }
    }
    if (new_pkey == NULL) {
        (void)EVP_PKEY_fromdata(pkctx, &new_pkey, EVP_PKEY_PUBLIC_KEY, params);
    }

    EVP_PKEY_CTX_free(pkctx);
    OSSL_PARAM_free(params);

    if (new_pkey != NULL) {
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = new_pkey;
    } else {
        /* If we cannot build a valid pkey with current components,
         * drop any stale pkey to reflect the cleared state. */
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = NULL;
    }
}

void libspdm_evp_export_to_cache(libspdm_rsa_ctx_evp_t *ctx)
{
    /* Export BNs from pkey if present and cache fields are empty */
    if (ctx == NULL || ctx->pkey == NULL) {
        return;
    }
    if (ctx->bn_n == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_N, &ctx->bn_n);
    }
    if (ctx->bn_e == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_E, &ctx->bn_e);
    }
    if (ctx->bn_d == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_D, &ctx->bn_d);
    }
    if (ctx->bn_p == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &ctx->bn_p);
    }
    if (ctx->bn_q == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &ctx->bn_q);
    }
    if (ctx->bn_dp == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &ctx->bn_dp);
    }
    if (ctx->bn_dq == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &ctx->bn_dq);
    }
    if (ctx->bn_q_inv == NULL) {
        EVP_PKEY_get_bn_param(ctx->pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &ctx->bn_q_inv);
    }
}

#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */
