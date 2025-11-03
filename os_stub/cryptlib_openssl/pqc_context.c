/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Post-Quantum Cryptography (PQC) Context Helper Functions Implementation.
 **/

#include "internal_crypt_lib.h"
#include "pqc_context.h"

#if LIBSPDM_ML_DSA_SUPPORT

const char *libspdm_mldsa_nid_to_name(size_t nid)
{
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_ML_DSA_44:
        return "ML-DSA-44";
    case LIBSPDM_CRYPTO_NID_ML_DSA_65:
        return "ML-DSA-65";
    case LIBSPDM_CRYPTO_NID_ML_DSA_87:
        return "ML-DSA-87";
    default:
        return NULL;
    }
}

#endif /* LIBSPDM_ML_DSA_SUPPORT */

#if LIBSPDM_SLH_DSA_SUPPORT

const char *libspdm_slhdsa_nid_to_name(size_t nid)
{
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S:
        return "SLH-DSA-SHA2-128s";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128S:
        return "SLH-DSA-SHAKE-128s";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128F:
        return "SLH-DSA-SHA2-128f";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_128F:
        return "SLH-DSA-SHAKE-128f";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192S:
        return "SLH-DSA-SHA2-192s";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192S:
        return "SLH-DSA-SHAKE-192s";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_192F:
        return "SLH-DSA-SHA2-192f";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_192F:
        return "SLH-DSA-SHAKE-192f";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S:
        return "SLH-DSA-SHA2-256s";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256S:
        return "SLH-DSA-SHAKE-256s";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256F:
        return "SLH-DSA-SHA2-256f";
    case LIBSPDM_CRYPTO_NID_SLH_DSA_SHAKE_256F:
        return "SLH-DSA-SHAKE-256f";
    default:
        return NULL;
    }
}

#endif /* LIBSPDM_SLH_DSA_SUPPORT */
