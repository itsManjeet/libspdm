/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include "ec_context.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include "rsa_context.h"

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

/**
 * Retrieve the RSA Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] rsa_context  Pointer to newly generated RSA context which contain the retrieved
 *                          RSA public key component. Use libspdm_rsa_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_rsa_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **rsa_context)
{
    bool status;
    BIO *der_bio;
    EVP_PKEY *pkey;

    /* Check input parameters.*/

    if (der_data == NULL || rsa_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;
    pkey = NULL;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }

    /* Retrieve RSA Public key from DER data as EVP_PKEY.*/
    pkey = d2i_PUBKEY_bio(der_bio, NULL);
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
        pkey = NULL; /* ownership moved */
    }

done:

    /* Release Resources.*/

    BIO_free(der_bio);

    return status;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
/**
 * Retrieve the EC Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data    Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size    size of the DER key data in bytes.
 * @param[out] ec_context  Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If der_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_ec_get_public_key_from_der(const uint8_t *der_data,
                                        size_t der_size,
                                        void **ec_context)
{
    bool status;
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;

    /* Check input parameters.*/

    if (der_data == NULL || ec_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "EC",
                                         OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
    if (dctx == NULL) {
        return false;
    }

    if (!OSSL_DECODER_from_data(dctx, &der_data, &der_size)) {
        goto done;
    }

    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        goto done;
    }

    /* Allocate wrapper structure */
    {
        libspdm_ec_context *ec_ctx;

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

    OSSL_DECODER_CTX_free(dctx);

    return status;
}
#endif /* LIBSPDM_ECDSA_SUPPORT */

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
/**
 * Retrieve the Ed Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] ecd_context  Pointer to newly generated Ed DSA context which contain the retrieved
 *                          Ed public key component. Use libspdm_ecd_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_ecd_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **ecd_context)
{
    bool status;
    BIO *der_bio;
    EVP_PKEY *pkey;
    int32_t type;

    /* Check input parameters.*/

    if (der_data == NULL || ecd_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }


    /* Retrieve Ed Public key from DER data.*/

    pkey = d2i_PUBKEY_bio(der_bio, NULL);
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

    BIO_free(der_bio);

    return status;
}
#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */

#if LIBSPDM_SM2_DSA_SUPPORT
/**
 * Retrieve the sm2 Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] sm2_context  Pointer to newly generated sm2 context which contain the retrieved
 *                          sm2 public key component. Use sm2_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_sm2_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **sm2_context)
{
    bool status;
    BIO *der_bio;
    EVP_PKEY *pkey = NULL;
    int result;

    /* Check input parameters.*/

    if (der_data == NULL || sm2_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }

    /* Retrieve sm2 Public key from DER data.*/

    pkey = d2i_PUBKEY_bio(der_bio, NULL);
    if (pkey == NULL) {
        goto done;
    }
    result = EVP_PKEY_is_a(pkey,"SM2");
    if (result == 0) {
        EVP_PKEY_free(pkey);
        goto done;
    }

    /* Allocate wrapper structure */
    {
        libspdm_ec_context *sm2_ctx = (libspdm_ec_context *)malloc(sizeof(libspdm_ec_context));
        if (sm2_ctx == NULL) {
            EVP_PKEY_free(pkey);
            goto done;
        }
        sm2_ctx->evp_pkey = pkey;
        *sm2_context = sm2_ctx;
        pkey = NULL; /* ownership moved to sm2_ctx */
        status = true;
    }

done:

    /* Release Resources.*/

    BIO_free(der_bio);

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return status;
}
#endif /* LIBSPDM_SM2_DSA_SUPPORT */
