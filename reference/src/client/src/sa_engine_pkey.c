/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa.h"
#include "sa_engine.h"
#include "sa_engine_internal.h"
#include "sa_log.h"
#include <openssl/engine.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000
int EVP_PKEY_CTX_md(
        EVP_PKEY_CTX* evp_pkey_ctx,
        int optype,
        int command,
        const char* message_digest) {
    if (message_digest == NULL) {
        ERROR("Invalid message digest");
        return 0;
    }

    const EVP_MD* evp_md = EVP_get_digestbyname(message_digest);
    if (evp_md == NULL) {
        ERROR("Invalid message digest");
        return 0;
    }

    return EVP_PKEY_CTX_ctrl(evp_pkey_ctx, -1, optype, command, 0, (void*) evp_md);
}
#endif

#define MAX_SIGNATURE_LENGTH 512
#define RSA_DEFAULT_PADDING_MODE RSA_PKCS1_PADDING
#define RSA_DEFAULT_PSS_SALT_LENGTH RSA_PSS_SALTLEN_AUTO

#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <memory.h>

#define EVP_PKEY_SECAPI3 0x53415F33

#define MAX_KEY_DATA_LEN 512

typedef struct {
    uint8_t data[MAX_KEY_DATA_LEN];
    int type;
    sa_key private_key;
} pkey_key_data;

#if defined(__linux__)
#include <malloc.h>
static size_t memory_size(const void* ptr, size_t default_size) {
    return malloc_usable_size((void*) ptr);
}
#elif defined(__APPLE__)
// https://www.unix.com/man-page/osx/3/malloc_size/
#include <malloc/malloc.h>
static int memory_size(void* ptr, size_t default_size) {
    return malloc_size(ptr);
}
#elif defined(_WIN32)
// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/msize
#include <malloc.h>
static int memory_size(void* ptr, size_t default_size) {
    return _msize((void*) ptr);
}
#else
static int memory_size(void* ptr, size_t default_size) {
    return default_size;
}
#endif

static sa_key get_pkey_key_data(EVP_PKEY* evp_pkey) {
    pkey_key_data* key_data = EVP_PKEY_get0(evp_pkey);
    if (key_data == NULL || key_data->type != EVP_PKEY_SECAPI3) {
        ERROR("EVP_PKEY_get0 failed");
        return UINT32_MAX;
    }

    return key_data->private_key;
}

// OpenSSL 1.0.2 and 1.1.1 don't have ex_data for an EVP_PKEY. So we have to make our own by getting the original
// allocated key, reallocating a larger space with our extended data, and putting back the new reallocated key.
static bool set_pkey_key_data(
        EVP_PKEY** evp_pkey,
        sa_key key) {

    bool result = false;
    int type = EVP_PKEY_id(*evp_pkey);
    void* temp_key = NULL;
    switch (type) {
        case EVP_PKEY_RSA:
            temp_key = EVP_PKEY_get1_RSA(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get1_RSA failed");
                break;
            }

            // Free the RSA evp_pkey to decrement the RSA reference count and create a new one to use.
            EVP_PKEY_free(*evp_pkey);
            *evp_pkey = EVP_PKEY_new();
            break;

        case EVP_PKEY_EC:
            temp_key = EVP_PKEY_get1_EC_KEY(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get1_EC_KEY failed");
                break;
            }

            // Free the EC evp_pkey to decrement the EC reference count and create a new one to use.
            EVP_PKEY_free(*evp_pkey);
            *evp_pkey = EVP_PKEY_new();
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
        case EVP_PKEY_X25519:
        case EVP_PKEY_X448:
            temp_key = EVP_PKEY_get0(*evp_pkey);
            if (temp_key == NULL) {
                ERROR("EVP_PKEY_get0 failed");
                break;
            }

            // Don't free a ED or X curve evp_pkey, it can be reused.
            break;
#endif

        default:
            break;
    }

    if (temp_key != NULL) {
        pkey_key_data* key_data = NULL;
        do {
            key_data = OPENSSL_malloc(sizeof(pkey_key_data));
            if (key_data == NULL) {
                ERROR("OPENSSL_malloc failed");
                break;
            }

            // Copy the original key data structure into another larger data structure.
            size_t temp_key_length = memory_size(temp_key, MAX_KEY_DATA_LEN);
            memcpy(key_data->data, temp_key, temp_key_length);

            // Free the original data structure (unless it's an ED or X key), but don't free any of it's contents which
            // are now pointed to by the key_data.
            if (type == EVP_PKEY_RSA || type == EVP_PKEY_EC)
                OPENSSL_free(temp_key);

            key_data->type = EVP_PKEY_SECAPI3;
            key_data->private_key = key;
            if (EVP_PKEY_assign(*evp_pkey, type, key_data) != 1) {
                ERROR("EVP_PKEY_assign failed");
                break;
            }

            // Assigned to evp_pkey;
            key_data = NULL;
            result = true;
        } while (false);

        if (key_data != NULL)
            OPENSSL_free(key_data);
    }

    return result;
}

#else
typedef struct {
    sa_key private_key;
} pkey_key_data;

static void pkey_key_data_new(
        void* parent,
        void* ptr,
        CRYPTO_EX_DATA* ad,
        int idx,
        long argl,
        void* argp) {

    CRYPTO_set_ex_data(ad, idx, OPENSSL_malloc(sizeof(pkey_key_data)));
}

static int pkey_key_data_dup(
        CRYPTO_EX_DATA* to,
        const CRYPTO_EX_DATA* from,
        void** from_d,
        int idx,
        long argl,
        void* argp) {

    pkey_key_data* from_key_data = CRYPTO_get_ex_data(from, idx);
    pkey_key_data* to_key_data = OPENSSL_malloc(sizeof(pkey_key_data));
    if (to_key_data == NULL) {
        ERROR("OPENSSL_malloc failed");
        return 0;
    }

    to_key_data->private_key = from_key_data->private_key;
    CRYPTO_set_ex_data(to, idx, OPENSSL_malloc(sizeof(pkey_key_data)));
    return 1;
}

static void pkey_key_data_free(
        void* parent,
        void* ptr,
        CRYPTO_EX_DATA* ad,
        int idx,
        long argl,
        void* argp) {

    pkey_key_data* key_data = CRYPTO_get_ex_data(ad, idx);
    OPENSSL_free(key_data);
}

static int get_ex_data_index() {
    static int index = 0;

    if (mtx_lock(&engine_mutex) != 0) {
        ERROR("mtx_lock failed");
        return 0;
    }

    if (index == 0) {
        index = EVP_PKEY_get_ex_new_index(0, NULL, pkey_key_data_new, pkey_key_data_dup, pkey_key_data_free);
    }

    mtx_unlock(&engine_mutex);
    return index;
}

static sa_key get_pkey_key_data(EVP_PKEY* evp_pkey) {
    pkey_key_data* key_data = EVP_PKEY_get_ex_data(evp_pkey, get_ex_data_index());
    if (key_data == NULL) {
        ERROR("EVP_PKEY_get_ex_data failed");
        return UINT32_MAX;
    }

    return key_data->private_key;
}

static bool set_pkey_key_data(EVP_PKEY** evp_pkey, sa_key key) {
    pkey_key_data* key_data = EVP_PKEY_get_ex_data(*evp_pkey, get_ex_data_index());
    if (key_data == NULL) {
        ERROR("OPENSSL_malloc failed");
        return false;
    }

    key_data->private_key = key;
    return true;
}
#endif

typedef struct {
    int padding_mode;
    int pss_salt_length;
    const EVP_MD_CTX* evp_md_ctx;
    const EVP_MD* evp_md;
} pkey_app_data;

static int pkey_nids[] = {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        EVP_PKEY_ED25519,
        EVP_PKEY_X25519,
        EVP_PKEY_ED448,
        EVP_PKEY_X448,
#endif
        EVP_PKEY_RSA,
        EVP_PKEY_EC,
        EVP_PKEY_DH};

static int pkey_nids_num = (sizeof(pkey_nids) / sizeof(pkey_nids[0]));
static EVP_PKEY_METHOD* rsa_pkey_method = NULL;
static EVP_PKEY_METHOD* ec_key_pkey_method = NULL;
static EVP_PKEY_METHOD* dh_pkey_method = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
static EVP_PKEY_METHOD* ed25519_pkey_method = NULL;
static EVP_PKEY_METHOD* x25519_pkey_method = NULL;
static EVP_PKEY_METHOD* ed448_pkey_method = NULL;
static EVP_PKEY_METHOD* x448_pkey_method = NULL;
#endif

static sa_digest_algorithm get_digest_algorithm(const EVP_MD* evp_md) {
    if (evp_md != NULL) {
        switch (EVP_MD_nid(evp_md)) {
            case NID_sha1:
                return SA_DIGEST_ALGORITHM_SHA1;

            case NID_sha256:
                return SA_DIGEST_ALGORITHM_SHA256;

            case NID_sha384:
                return SA_DIGEST_ALGORITHM_SHA384;

            case NID_sha512:
                return SA_DIGEST_ALGORITHM_SHA512;
        }
    }

    return UINT32_MAX;
}

static int pkey_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    pkey_app_data* app_data = OPENSSL_malloc(sizeof(pkey_app_data));
    if (app_data == NULL) {
        ERROR("malloc failed");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("EVP_PKEY_CTX_get0_pkey failed");
        return 0;
    }

    int key_type = EVP_PKEY_base_id(evp_pkey);
    if (key_type == EVP_PKEY_RSA) {
        app_data->padding_mode = RSA_DEFAULT_PADDING_MODE;
        app_data->pss_salt_length = RSA_DEFAULT_PSS_SALT_LENGTH;
    } else {
        app_data->padding_mode = 0;
        app_data->pss_salt_length = 0;
    }

    app_data->evp_md_ctx = NULL;
    app_data->evp_md = NULL;
    EVP_PKEY_CTX_set_app_data(evp_pkey_ctx, app_data);
    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
static int pkey_copy(
        EVP_PKEY_CTX* dst_evp_pkey_ctx,
        const EVP_PKEY_CTX* src_evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data((EVP_PKEY_CTX*) src_evp_pkey_ctx);
#else
static int pkey_copy(
        EVP_PKEY_CTX* dst_evp_pkey_ctx,
        EVP_PKEY_CTX* src_evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(src_evp_pkey_ctx);
#endif
    pkey_app_data* new_app_data = OPENSSL_malloc(sizeof(pkey_app_data));
    if (new_app_data == NULL) {
        ERROR("malloc failed");
        return 0;
    }

    new_app_data->padding_mode = app_data->padding_mode;
    new_app_data->pss_salt_length = app_data->pss_salt_length;
    new_app_data->evp_md_ctx = app_data->evp_md_ctx;
    new_app_data->evp_md = app_data->evp_md;

    EVP_PKEY_CTX_set_app_data(dst_evp_pkey_ctx, new_app_data);
    return 1;
}

static void pkey_cleanup(EVP_PKEY_CTX* evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data != NULL)
        OPENSSL_free(app_data);
}

static int pkey_signverify_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    return 1;
}

static int pkey_sign(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* signature,
        size_t* signature_length,
        const unsigned char* data,
        size_t data_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return 0;
    }

    if (data == NULL) {
        ERROR("NULL data");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    sa_key key = get_pkey_key_data(evp_pkey);
    sa_header header;
    if (sa_key_header(&header, key) != SA_STATUS_OK) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    sa_signature_algorithm signature_algorithm;
    sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
    sa_sign_parameters_rsa_pss parameters_rsa_pss;
    sa_sign_parameters_ecdsa parameters_ecdsa;
    void* parameters = NULL;
    switch (header.type) {
        case SA_KEY_TYPE_RSA:
            if (app_data->padding_mode == RSA_PKCS1_PADDING) {
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15;
                parameters_rsa_pkcs1v15.digest_algorithm = get_digest_algorithm(app_data->evp_md);
                if (parameters_rsa_pkcs1v15.digest_algorithm == UINT32_MAX) {
                    ERROR("digest_algorithm unknown");
                    return 0;
                }

                parameters_rsa_pkcs1v15.precomputed_digest = true;
                parameters = &parameters_rsa_pkcs1v15;
            } else if (app_data->padding_mode == RSA_PKCS1_PSS_PADDING) {
                signature_algorithm = SA_SIGNATURE_ALGORITHM_RSA_PSS;
                parameters_rsa_pss.digest_algorithm = get_digest_algorithm(app_data->evp_md);
                if (parameters_rsa_pss.digest_algorithm == UINT32_MAX) {
                    ERROR("digest_algorithm unknown");
                    return 0;
                }

                parameters_rsa_pss.precomputed_digest = true;
                int salt_length;
                if (app_data->pss_salt_length == RSA_PSS_SALTLEN_DIGEST) {
                    salt_length = EVP_MD_size(app_data->evp_md);
                } else if (app_data->pss_salt_length == RSA_PSS_SALTLEN_AUTO ||
                           app_data->pss_salt_length == RSA_PSS_SALTLEN_MAX) {
                    salt_length = EVP_PKEY_size(evp_pkey) - EVP_MD_size(app_data->evp_md) - 2;
                    if ((EVP_PKEY_bits(evp_pkey) & 0x7) == 1)
                        salt_length--;

                    if (salt_length < 0) {
                        ERROR("digest_algorithm unknown");
                        return 0;
                    }
                } else
                    salt_length = app_data->pss_salt_length;

                parameters_rsa_pss.salt_length = salt_length;
                parameters = &parameters_rsa_pss;
            } else {
                ERROR("Invalid padding mode");
                return 0;
            }

            break;

        case SA_KEY_TYPE_EC:
            if (!is_pcurve(header.param)) {
                ERROR("Invalid EC curve");
                return 0;
            }

            signature_algorithm = SA_SIGNATURE_ALGORITHM_ECDSA;
            parameters_ecdsa.digest_algorithm = get_digest_algorithm(app_data->evp_md);
            if (parameters_ecdsa.digest_algorithm == UINT32_MAX) {
                ERROR("digest_algorithm unknown");
                return 0;
            }

            parameters_ecdsa.precomputed_digest = true;
            parameters = &parameters_ecdsa;
            break;

        default:
            ERROR("Invalid key type");
            return 0;
    }

    uint8_t local_signature[MAX_SIGNATURE_LENGTH];
    size_t local_signature_length = MAX_SIGNATURE_LENGTH;
    if (sa_crypto_sign(local_signature, &local_signature_length, signature_algorithm, key, data, data_length,
                parameters) != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
    }

    if (header.type == SA_KEY_TYPE_EC) {
        // Take the SecApi 3 signature and encode it like OpenSSL would so that it looks like it came from
        // OpenSSL
        if (signature != NULL) {
            if (!ec_encode_signature(signature, signature_length, local_signature, local_signature_length)) {
                ERROR("ec_encode_signature failed");
                return 0;
            }
        } else {
            // Add the most number of bytes that can be added by ASN.1 encoding (9). It could be as few as 6.
            *signature_length = local_signature_length + 9;
        }
    } else {
        if (signature != NULL)
            memcpy(signature, local_signature, local_signature_length);

        *signature_length = local_signature_length;
    }

    return 1;
}

static int pkey_verify(
        EVP_PKEY_CTX* evp_pkey_ctx,
        const unsigned char* signature,
        size_t signature_length,
        const unsigned char* data,
        size_t data_length) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (signature == NULL) {
        ERROR("NULL signature");
        return 0;
    }

    if (data == NULL) {
        ERROR("NULL data");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int result = 0;
    int key_type = EVP_PKEY_base_id(evp_pkey);
    EVP_PKEY* verify_pkey = NULL;
    EVP_PKEY_CTX* verify_pkey_ctx = NULL;
    do {
        sa_key verify_key = get_pkey_key_data(evp_pkey);
        verify_pkey = get_public_key(verify_key);
        if (verify_pkey == NULL) {
            ERROR("NULL verify_pkey");
            break;
        }

        verify_pkey_ctx = EVP_PKEY_CTX_new(verify_pkey, NULL);
        if (verify_pkey_ctx == NULL) {
            ERROR("NULL verify_pkey_ctx");
            break;
        }

        if (EVP_PKEY_verify_init(verify_pkey_ctx) != 1) {
            ERROR("EVP_PKEY_verify_init failed");
            break;
        }

        if (key_type == EVP_PKEY_RSA) {
            if (EVP_PKEY_CTX_set_rsa_padding(verify_pkey_ctx, app_data->padding_mode) != 1) {
                ERROR("EVP_PKEY_CTX_set_rsa_padding failed");
                break;
            }

            if (app_data->padding_mode == RSA_PKCS1_PSS_PADDING) {
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_pkey_ctx, app_data->pss_salt_length) != 1) {
                    ERROR("EVP_PKEY_CTX_set_rsa_pss_saltlen failed");
                    break;
                }
            }
        }

        if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_EC) {
            if (EVP_PKEY_CTX_set_signature_md(verify_pkey_ctx, app_data->evp_md) != 1) {
                ERROR("EVP_PKEY_CTX_set_signature_md failed");
                break;
            }
        }

        if (EVP_PKEY_verify(verify_pkey_ctx, signature, signature_length, data, data_length) != 1) {
            ERROR("EVP_PKEY_verify");
            break;
        }

        result = 1;
    } while (false);

    EVP_PKEY_CTX_free(verify_pkey_ctx);
    EVP_PKEY_free(verify_pkey);
    return result;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
static int pkey_digestsign(
        EVP_MD_CTX* evp_md_ctx,
        unsigned char* signature,
        size_t* signature_length,
        const unsigned char* data,
        size_t data_length) {

    if (evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return 0;
    }

    if (data == NULL) {
        ERROR("NULL data");
        return 0;
    }

    EVP_PKEY_CTX* evp_pkey_ctx = EVP_MD_CTX_pkey_ctx(evp_md_ctx);
    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    sa_key key = get_pkey_key_data(evp_pkey);
    sa_header header;
    if (sa_key_header(&header, key) != SA_STATUS_OK) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    if (header.type != SA_KEY_TYPE_EC &&
            !(header.param == SA_ELLIPTIC_CURVE_ED25519 || header.param == SA_ELLIPTIC_CURVE_ED448)) {
        ERROR("Invalid key type");
        return 0;
    }

    sa_signature_algorithm signature_algorithm = SA_SIGNATURE_ALGORITHM_EDDSA;
    if (sa_crypto_sign(signature, signature_length, signature_algorithm, key, data, data_length,
                NULL) != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
    }

    return 1;
}

static int pkey_digestverify(
        EVP_MD_CTX* evp_md_ctx,
        const unsigned char* signature,
        size_t signature_length,
        const unsigned char* data,
        size_t data_length) {

    if (evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    if (signature == NULL) {
        ERROR("NULL signature");
        return 0;
    }

    if (data == NULL) {
        ERROR("NULL data");
        return 0;
    }

    EVP_PKEY_CTX* evp_pkey_ctx = EVP_MD_CTX_pkey_ctx(evp_md_ctx);
    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    int result = 0;
    EVP_PKEY* verify_pkey = NULL;
    EVP_MD_CTX* verify_md_ctx = NULL;
    do {
        sa_key verify_key = get_pkey_key_data(evp_pkey);
        verify_pkey = get_public_key(verify_key);
        if (verify_pkey == NULL) {
            ERROR("NULL verify_pkey");
            break;
        }

        verify_md_ctx = EVP_MD_CTX_new();
        if (verify_md_ctx == NULL) {
            ERROR("NULL verify_md_ctx");
            break;
        }

        if (EVP_DigestVerifyInit(verify_md_ctx, NULL, NULL, NULL, verify_pkey) != 1) {
            ERROR("EVP_DigestVerifyinit failed");
            break;
        }

        if (EVP_DigestVerify(verify_md_ctx, signature, signature_length, data, data_length) != 1) {
            ERROR("EVP_DigestVerify");
            break;
        }

        result = 1;
    } while (false);

    EVP_MD_CTX_free(verify_md_ctx);
    EVP_PKEY_free(verify_pkey);
    return result;
}
#endif

static int pkey_encrypt_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    return 0;
}

static int pkey_encrypt(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* out,
        size_t* outlen,
        const unsigned char* in,
        size_t inlen) {
    return 0;
}

static int pkey_decrypt_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    return 0;
}

static int pkey_decrypt(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* out,
        size_t* outlen,
        const unsigned char* in,
        size_t inlen) {
    return 0;
}

static int pkey_ctrl(
        EVP_PKEY_CTX* evp_pkey_ctx,
        int type,
        int p1,
        void* p2) {

    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data(evp_pkey_ctx);
    if (app_data == NULL) {
        ERROR("NULL app_data");
        return 0;
    }

    switch (type) {
        case EVP_PKEY_CTRL_DIGESTINIT:
            app_data->evp_md_ctx = p2;
            break;

        case EVP_PKEY_CTRL_MD:
            app_data->evp_md = p2;
            break;

        case EVP_PKEY_CTRL_GET_MD:
            if (p2 == NULL) {
                ERROR("NULL p2");
                return 0;
            }

            *(const EVP_MD**) p2 = app_data->evp_md;
            break;

        case EVP_PKEY_CTRL_RSA_PADDING:
            app_data->padding_mode = p1;
            break;

        case EVP_PKEY_CTRL_GET_RSA_PADDING:
            if (p2 == NULL) {
                ERROR("NULL p2");
                return 0;
            }

            *((int*) p2) = app_data->padding_mode;
            break;

        case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
            if (app_data->padding_mode != RSA_PKCS1_PSS_PADDING) {
                ERROR("Invalid padding mode for EVP_PKEY_CTRL_RSA_PSS_SALTLEN");
                return 0;
            }

            app_data->pss_salt_length = p1;
            break;

        case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
            if (app_data->padding_mode != RSA_PKCS1_PSS_PADDING) {
                ERROR("Invalid padding mode for EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN");
                return 0;
            }

            if (p2 == NULL) {
                ERROR("NULL p2");
                return 0;
            }

            *((int*) p2) = app_data->pss_salt_length;
            break;

        case EVP_PKEY_CTRL_PKCS7_SIGN:
            // Just checks if approved for PKCS7 signing.
            break;

        default:
            return -2;
    }

    return 1;
}

static int pkey_ctrl_str(
        EVP_PKEY_CTX* evp_pkey_ctx,
        const char* type,
        const char* value) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (type == NULL) {
        ERROR("NULL type");
        return 0;
    }

    if (value == NULL) {
        ERROR("NULL value");
        return 0;
    }

    if (strcmp(type, "rsa_padding_mode") == 0) {
        int pm;
        if (strcmp(value, "pkcs1") == 0)
            pm = RSA_PKCS1_PADDING;
        else if (strcmp(value, "oaep") == 0)
            pm = RSA_PKCS1_OAEP_PADDING;
        else if (strcmp(value, "pss") == 0)
            pm = RSA_PKCS1_PSS_PADDING;
        else {
            ERROR("Invalid padding mode");
            return -2;
        }

        return EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, pm);
    }

    if (strcmp(type, "rsa_pss_saltlen") == 0) {
        int saltlen;

        if (!strcmp(value, "digest"))
            saltlen = RSA_PSS_SALTLEN_DIGEST;
        else if (!strcmp(value, "max"))
            saltlen = RSA_PSS_SALTLEN_MAX;
        else if (!strcmp(value, "auto"))
            saltlen = RSA_PSS_SALTLEN_AUTO;
        else
            saltlen = atoi(value);

        return EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ctx, saltlen);
    }

    if (strcmp(type, "rsa_oaep_md") == 0)
        return EVP_PKEY_CTX_md(evp_pkey_ctx, EVP_PKEY_OP_TYPE_CRYPT,
                EVP_PKEY_CTRL_RSA_OAEP_MD, value);

    return -2;
}

static int pkey_pderive_init(EVP_PKEY_CTX* ctx) {
    return 0;
}

static int pkey_pderive(
        EVP_PKEY_CTX* ctx,
        unsigned char* key,
        size_t* keylen) {
    return 0;
}

static EVP_PKEY_METHOD* get_pkey_method(
        int nid,
        bool custom_signature) {
    EVP_PKEY_METHOD* evp_pkey_method = EVP_PKEY_meth_new(nid,
            EVP_PKEY_FLAG_AUTOARGLEN | (custom_signature ? EVP_PKEY_FLAG_SIGCTX_CUSTOM : 0));
    if (evp_pkey_method != NULL) {
        EVP_PKEY_meth_set_init(evp_pkey_method, pkey_init);
        EVP_PKEY_meth_set_copy(evp_pkey_method, pkey_copy);
        EVP_PKEY_meth_set_cleanup(evp_pkey_method, pkey_cleanup);
        EVP_PKEY_meth_set_ctrl(evp_pkey_method, pkey_ctrl, pkey_ctrl_str);
    }

    return evp_pkey_method;
}

EVP_PKEY* sa_key_to_EVP_PKEY(sa_key key) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    // Call get_ex_data_index to initialize ex_data before getting the public key. This may be the first time its
    // been called.
    get_ex_data_index();
#endif
    EVP_PKEY* evp_pkey = get_public_key(key);
    if (!set_pkey_key_data(&evp_pkey, key)) {
        ERROR("set_pkey_key_data failed");
        EVP_PKEY_free(evp_pkey);
        return NULL;
    }

    ENGINE* engine = sa_get_engine();
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    if (EVP_PKEY_set1_engine(evp_pkey, engine) != 1) {
        ERROR("EVP_PKEY_set1_engine failed");
        EVP_PKEY_free(evp_pkey);
        ENGINE_free(engine);
        return NULL;
    }
#else
    if (evp_pkey->engine != NULL)
        ENGINE_finish(evp_pkey->engine);

    evp_pkey->engine = engine;
    ENGINE_init(evp_pkey->engine);
#endif
    ENGINE_free(engine);
    return evp_pkey;
}

int sa_get_engine_pkey_methods(
        ENGINE* engine,
        EVP_PKEY_METHOD** method,
        const int** nids,
        int nid) {

    if (!method) {
        if (nids == NULL)
            return 0;

        *nids = pkey_nids;
        return pkey_nids_num;
    }

    if (mtx_lock(&engine_mutex) != 0) {
        ERROR("mtx_lock failed");
        return 0;
    }

    if (nid == EVP_PKEY_RSA) {
        if (rsa_pkey_method == NULL) {
            rsa_pkey_method = get_pkey_method(EVP_PKEY_RSA, false);
            EVP_PKEY_meth_set_sign(rsa_pkey_method, pkey_signverify_init, pkey_sign);
            EVP_PKEY_meth_set_verify(rsa_pkey_method, pkey_signverify_init, pkey_verify);
            EVP_PKEY_meth_set_encrypt(rsa_pkey_method, pkey_encrypt_init, pkey_encrypt);
            EVP_PKEY_meth_set_decrypt(rsa_pkey_method, pkey_decrypt_init, pkey_decrypt);
        }

        *method = rsa_pkey_method;
    } else if (nid == EVP_PKEY_EC) {
        if (ec_key_pkey_method == NULL) {
            ec_key_pkey_method = get_pkey_method(EVP_PKEY_EC, false);
            EVP_PKEY_meth_set_sign(ec_key_pkey_method, pkey_signverify_init, pkey_sign);
            EVP_PKEY_meth_set_verify(ec_key_pkey_method, pkey_signverify_init, pkey_verify);
            EVP_PKEY_meth_set_derive(ec_key_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = ec_key_pkey_method;
    } else if (nid == EVP_PKEY_DH) {
        if (dh_pkey_method == NULL) {
            dh_pkey_method = get_pkey_method(EVP_PKEY_DH, false);
            EVP_PKEY_meth_set_derive(dh_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = dh_pkey_method;
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    } else if (nid == EVP_PKEY_ED25519) {
        if (ed25519_pkey_method == NULL) {
            ed25519_pkey_method = get_pkey_method(EVP_PKEY_ED25519, true);
            EVP_PKEY_meth_set_digestsign(ed25519_pkey_method, pkey_digestsign);
            EVP_PKEY_meth_set_digestverify(ed25519_pkey_method, pkey_digestverify);
        }

        *method = ed25519_pkey_method;
    } else if (nid == EVP_PKEY_X25519) {
        if (x25519_pkey_method == NULL) {
            x25519_pkey_method = get_pkey_method(EVP_PKEY_X25519, false);
            EVP_PKEY_meth_set_derive(x25519_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = x25519_pkey_method;
    } else if (nid == EVP_PKEY_ED448) {
        if (ed448_pkey_method == NULL) {
            ed448_pkey_method = get_pkey_method(EVP_PKEY_ED448, true);
            EVP_PKEY_meth_set_digestsign(ed448_pkey_method, pkey_digestsign);
            EVP_PKEY_meth_set_digestverify(ed448_pkey_method, pkey_digestverify);
        }

        *method = ed448_pkey_method;
    } else if (nid == EVP_PKEY_X448) {
        if (x448_pkey_method == NULL) {
            x448_pkey_method = get_pkey_method(EVP_PKEY_X448, false);
            EVP_PKEY_meth_set_derive(x448_pkey_method, pkey_pderive_init, pkey_pderive);
        }

        *method = x448_pkey_method;
#endif
    } else {
        *method = NULL;
    }

    mtx_unlock(&engine_mutex);
    return *method == NULL ? 0 : 1;
}
