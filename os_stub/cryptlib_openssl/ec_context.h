/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * EC context wrapper structure definition.
 **/

#ifndef __EC_CONTEXT_H__
#define __EC_CONTEXT_H__

#include <openssl/evp.h>

/**
 * EC context wrapper structure
 * Wraps EVP_PKEY to provide a clean interface and future extensibility
 */
typedef struct {
    EVP_PKEY *evp_pkey;
} libspdm_ec_context;

/**
 * Helper macro to get EVP_PKEY from ec_context
 */
#define EC_CTX_TO_EVP_PKEY(ec_ctx) (((libspdm_ec_context *)(ec_ctx))->evp_pkey)

#endif
