/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include "ec_context.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>
#include "rsa_context.h"

static size_t ascii_str_len(const char *string)
{
    size_t length;

    LIBSPDM_ASSERT(string != NULL);
    if (string == NULL) {
        return 0;
    }

    for (length = 0; *string != '\0'; string++, length++) {
        ;
    }
    return length;
}

/**
 * Callback function for password phrase conversion used for retrieving the encrypted PEM.
 *
 * @param[out]  buf      Pointer to the buffer to write the passphrase to.
 * @param[in]   size     Maximum length of the passphrase (i.e. the size of buf).
 * @param[in]   flag     A flag which is set to 0 when reading and 1 when writing.
 * @param[in]   key      key data to be passed to the callback routine.
 *
 * @retval  The number of characters in the passphrase or 0 if an error occurred.
 *
 **/
int PasswordCallback(char *buf, const int size, const int flag, const void *key)
{
    int key_length;

    libspdm_zero_mem((void *)buf, (size_t)size);
    if (key != NULL) {

        /* Duplicate key phrase directly.*/

        key_length = (int)ascii_str_len((char *)key);
        key_length = (key_length > size) ? size : key_length;
        libspdm_copy_mem(buf, size, key, (size_t)key_length);
        return key_length;
    } else {
        return 0;
    }
}

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] rsa_context   Pointer to newly generated RSA context which contain the retrieved
 *                         RSA private key component. Use libspdm_rsa_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_rsa_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **rsa_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;

    if (pem_data == NULL || rsa_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    status = false;
    pkey = NULL;

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        goto done;
    }

    {
        libspdm_rsa_ctx_evp_t *ctx;
        ctx = (libspdm_rsa_ctx_evp_t *)allocate_pool(sizeof(libspdm_rsa_ctx_evp_t));
        if (ctx == NULL) {
            goto done;
        }
        libspdm_zero_mem(ctx, sizeof(*ctx));
        ctx->pkey = pkey;
        *rsa_context = (void *)ctx;
        status = true;
        pkey = NULL; /* ownership moved to ctx */
    }

done:
    BIO_free(pem_bio);
    if (!status && pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    return status;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

/**
 * Retrieve the EC Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ec_context    Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC private key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_ec_get_private_key_from_pem(const uint8_t *pem_data, size_t pem_size,
                                         const char *password,
                                         void **ec_context)
{
    bool status;
    BIO *pem_bio;

    /* Check input parameters.*/

    if (pem_data == NULL || ec_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }


    /* Retrieve EC Private key from encrypted PEM data.*/
    {
        EVP_PKEY *pkey;
        libspdm_ec_context *ec_ctx;

        pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                       (pem_password_cb *)&PasswordCallback,
                                       (void *)password);
        if (pkey == NULL) {
            goto done;
        }

        if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
            EVP_PKEY_free(pkey);
            goto done;
        }

        /* Allocate wrapper structure */
        ec_ctx = (libspdm_ec_context *)malloc(sizeof(libspdm_ec_context));
        if (ec_ctx == NULL) {
            EVP_PKEY_free(pkey);
            goto done;
        }
        ec_ctx->evp_pkey = pkey;
        *ec_context = ec_ctx;
        status = true;
    }

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}

/**
 * Retrieve the Ed Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ecd_context    Pointer to newly generated Ed DSA context which contain the retrieved
 *                         Ed private key component. Use libspdm_ecd_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_ecd_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **ecd_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;
    int32_t type;

    /* Check input parameters.*/

    if (pem_data == NULL || ecd_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }


    /* Retrieve Ed Private key from encrypted PEM data.*/

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }
    type = EVP_PKEY_id(pkey);
    if ((type != EVP_PKEY_ED25519) && (type != EVP_PKEY_ED448)) {
        EVP_PKEY_free(pkey);
        goto done;
    }

    /* Create double pointer structure for EdDSA context (compatible with libspdm_ecd_new_by_nid) */
    EVP_PKEY **ecd_context_ptr = malloc(sizeof(EVP_PKEY *));
    if (ecd_context_ptr == NULL) {
        EVP_PKEY_free(pkey);
        goto done;
    }
    *ecd_context_ptr = pkey;
    *ecd_context = ecd_context_ptr;
    status = true;

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}

/**
 * Retrieve the sm2 Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] sm2_context   Pointer to newly generated sm2 context which contain the retrieved
 *                         sm2 private key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_sm2_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **sm2_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;
    char curve_name[64] = {0};
    size_t curve_name_len = sizeof(curve_name);
    int32_t openssl_nid;

    /* Check input parameters.*/
    if (pem_data == NULL || sm2_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    status = false;
    pkey = NULL;

    /* Read encrypted PEM data.*/
    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    /* Retrieve SM2 Private key from encrypted PEM data.*/
    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }

    /* Use modern parameter interface instead of EVP_PKEY_get0_EC_KEY
     * Get curve name*/
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                       curve_name, sizeof(curve_name),
                                       &curve_name_len) <= 0) {
        goto done;
    }

    /* Convert curve name to NID */
    openssl_nid = OBJ_sn2nid(curve_name);
    if (openssl_nid != NID_sm2) {
        goto done;
    }

    /* Allocate wrapper structure */
    {
        libspdm_ec_context *sm2_ctx = (libspdm_ec_context *)malloc(sizeof(libspdm_ec_context));
        if (sm2_ctx == NULL) {
            goto done;
        }
        sm2_ctx->evp_pkey = pkey;
        *sm2_context = sm2_ctx;
        pkey = NULL; /* ownership moved to sm2_ctx */
        status = true;
    }

done:
    /* Release Resources.*/
    BIO_free(pem_bio);

    /* Free pkey if failed */
    if (!status && pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return status;
}
