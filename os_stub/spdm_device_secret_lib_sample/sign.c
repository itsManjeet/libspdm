/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openssl/store.h>
#include <dlfcn.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <base.h>
#include "library/memlib.h"
#include "openssllib/openssl/include/openssl/evp.h"
#include "openssllib/openssl/include/openssl/provider.h"
#include "openssllib/openssl/include/openssl/store.h"
#include "openssllib/openssl_gen/openssl/crypto.h"
#include "openssllib/openssl_gen/openssl/err.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_requester_private_key(
            req_base_asym_alg, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_get_private_key_from_pem(req_base_asym_alg,
                                                           private_pem,
                                                           private_pem_size, NULL,
                                                           &context);
        if (!result) {
            libspdm_zero_mem(private_pem, private_pem_size);
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_req_asym_sign_hash(spdm_version, op_code, req_base_asym_alg,
                                                base_hash_algo, context,
                                                message, message_size, signature, sig_size);
        } else {
            result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                           base_hash_algo, context,
                                           message, message_size,
                                           signature, sig_size);
        }
        libspdm_req_asym_free(req_base_asym_alg, context);
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    } else {
#endif
    result = libspdm_get_requester_private_key_from_raw_data(req_base_asym_alg, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_req_asym_sign_hash(spdm_version, op_code, req_base_asym_alg,
                                            base_hash_algo, context,
                                            message, message_size, signature, sig_size);
    } else {
        result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                       base_hash_algo, context,
                                       message, message_size,
                                       signature, sig_size);
    }
    libspdm_req_asym_free(req_base_asym_alg, context);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

#if LIBSPDM_SECRET_LIB_SIGN_LITTLE_ENDIAN
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) <= SPDM_MESSAGE_VERSION_11) {
        if (result) {
            libspdm_copy_signature_swap_endian(
                req_base_asym_alg, signature, *sig_size, signature, *sig_size);
        }
    }
#endif

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        // result = libspdm_read_responder_private_key(
        //     base_asym_algo, &private_pem, &private_pem_size);
        // if (!result) {
        //     return false;
        // }

        // result = libspdm_asym_get_private_key_from_pem(
        //     base_asym_algo, private_pem, private_pem_size, NULL, &context);
        // if (!result) {
        //     libspdm_zero_mem(private_pem, private_pem_size);
        //     free(private_pem);
        //     return false;
        // }
        //

        OSSL_STORE_INFO *info = NULL;
        EVP_PKEY *pkey = NULL;

        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

        OSSL_PROVIDER_set_default_search_path(libctx, "/usr/lib/aarch64-linux-gnu/ossl-modules/");

        void *tpm2_handler = dlopen("/usr/lib/aarch64-linux-gnu/ossl-modules/tpm2.so", RTLD_GLOBAL | RTLD_NOW);
        if (tpm2_handler == NULL) {
            printf("ERROR: %s\n", dlerror());
            return false;
        }

        int (*tpm2_init_fun)(const OSSL_CORE_HANDLE *handle,
                                            const OSSL_DISPATCH *in,
                                            const OSSL_DISPATCH **out,
                                            void **provctx) =  dlsym(tpm2_handler, "OSSL_provider_init");

        if (tpm2_init_fun == NULL) {
            printf("ERROR: %s\n", dlerror());
            dlclose(tpm2_handler);
            return false;
        }

        if (OSSL_PROVIDER_add_builtin(libctx, "tpm2", tpm2_init_fun) <=0) {
            printf("TPM2_add builtin failed\n");
            return false;
        }

        const char* search_path = OSSL_PROVIDER_get0_default_search_path(libctx);
        printf("SEARCH_PATH: %s\n", search_path);

        OSSL_PROVIDER *tpm2_provider = OSSL_PROVIDER_load(libctx, "tpm2");
        if (!tpm2_provider) {
            unsigned int err = ERR_get_error();
            printf("ERROR: %s\n",ERR_reason_error_string(err));
            return false;
        }

        if (OSSL_PROVIDER_self_test(tpm2_provider) <= 0) {
            unsigned int err = ERR_get_error();
            printf("ERROR: %s\n",ERR_reason_error_string(err));
            OSSL_PROVIDER_unload(tpm2_provider);
            dlclose(tpm2_handler);
            return false;
        }

        if (OSSL_PROVIDER_available(libctx, "tpm2")) {
            printf("TPM2 provider is available.\n");
        } else {
            printf("TPM2 provider is not available.\n");
        }


        OSSL_PROVIDER *default_provider = OSSL_PROVIDER_load(libctx, "default");
        if (!default_provider) {
            return false;
        }

        OSSL_STORE_CTX* store_ctx = OSSL_STORE_open_ex("handle:0x81010002", libctx, "?provider=tpm2", NULL, NULL, NULL, NULL, NULL);
        if (!store_ctx) {
            unsigned int err = ERR_get_error();
            printf("ERROR: store_ctx %d %s\n", err, ERR_reason_error_string(err));
            return false;
        }

        printf("STORE_CTX: got handle %p\n", store_ctx);

        static int counter = 0;
        while ((info = OSSL_STORE_load(store_ctx)) != NULL) {
            printf("info counter = %d\n", counter);
            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                printf("Got key at %d\n", counter);
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
                printf("Got key at %d DONE\n", counter);
                break;
            }
        }
        if (pkey == NULL) {
            printf("PKEY == null\n");
            return false;
        }

        printf("PKEY got %p\n", pkey);
        context = (void *) pkey;

        if (is_data_hash) {
            result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                            context,
                                            message, message_size, signature, sig_size);
        } else {
            result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
                                       base_hash_algo, context,
                                       message, message_size,
                                       signature, sig_size);
        }
        libspdm_asym_free(base_asym_algo, context);
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    } else {
#endif
    result = libspdm_get_responder_private_key_from_raw_data(base_asym_algo, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                        context,
                                        message, message_size, signature, sig_size);
    } else {
        result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
                                   base_hash_algo, context,
                                   message, message_size,
                                   signature, sig_size);
    }
    libspdm_asym_free(base_asym_algo, context);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

#if LIBSPDM_SECRET_LIB_SIGN_LITTLE_ENDIAN
    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) <= SPDM_MESSAGE_VERSION_11) {
        if (result) {
            libspdm_copy_signature_swap_endian(
                base_asym_algo, signature, *sig_size, signature, *sig_size);
        }
    }
#endif

    return result;
}
