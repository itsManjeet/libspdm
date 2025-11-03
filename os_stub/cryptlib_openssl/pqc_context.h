/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Post-Quantum Cryptography (PQC) Context Structures and Helper Functions.
 **/

#ifndef __PQC_CONTEXT_H__
#define __PQC_CONTEXT_H__

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

#if LIBSPDM_ML_DSA_SUPPORT

/**
 * ML-DSA context structure.
 **/
typedef struct {
    EVP_PKEY *pkey;
    size_t nid; /* LIBSPDM_CRYPTO_NID_ML_DSA_xx */
} libspdm_mldsa_ctx;

/**
 * Convert ML-DSA NID to algorithm name string.
 *
 * @param[in]  nid  ML-DSA NID.
 *
 * @return  Algorithm name string, or NULL if nid is invalid.
 **/
const char *libspdm_mldsa_nid_to_name(size_t nid);

#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

/**
 * SLH-DSA context structure.
 **/
typedef struct {
    EVP_PKEY *pkey;
    size_t nid;
} libspdm_slhdsa_ctx;

/**
 * Convert SLH-DSA NID to algorithm name string.
 *
 * @param[in]  nid  SLH-DSA NID.
 *
 * @return  Algorithm name string, or NULL if nid is invalid.
 **/
const char *libspdm_slhdsa_nid_to_name(size_t nid);

#endif /* LIBSPDM_SLH_DSA_SUPPORT */

#endif /* __PQC_CONTEXT_H__ */
