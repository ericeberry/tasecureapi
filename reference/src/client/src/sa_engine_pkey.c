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
#include "sa_engine_internal.h"
#include "sa_log.h"
#include <memory.h>
#include <openssl/engine.h>

// Flag defined in openssl/evp_int.h
#define EVP_MD_CTX_FLAG_KEEP_PKEY_CTX 0x0400

#define EVP_PKEY_SECAPI3 0x53415F33

typedef struct {
    int padding_mode;
    int pss_salt_length;
    EVP_MD_CTX* evp_md_ctx;
    const EVP_MD* evp_md;
} pkey_app_data;

#define MAX_KEY_DATA_LEN 512

typedef struct {
    uint8_t data[MAX_KEY_DATA_LEN];
    int type;
    sa_key private_key;
} pkey_key_data;

static int pkey_nids[] = {
        EVP_PKEY_RSA,
        EVP_PKEY_EC,
        EVP_PKEY_DH};

static int pkey_nids_num = (sizeof(pkey_nids) / sizeof(pkey_nids[0]));
static EVP_PKEY_METHOD* rsa_pkey_method = NULL;
static EVP_PKEY_METHOD* ec_key_pkey_method = NULL;
static EVP_PKEY_METHOD* dh_pkey_method = NULL;

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

    app_data->padding_mode = 0;
    app_data->pss_salt_length = 0;
    app_data->evp_md_ctx = NULL;
    app_data->evp_md = NULL;
    EVP_PKEY_CTX_set_app_data(evp_pkey_ctx, app_data);
    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000
static int pkey_copy(
        EVP_PKEY_CTX* dst_evp_pkey_ctx,
        const EVP_PKEY_CTX* src_evp_pkey_ctx) {
    pkey_app_data* app_data = EVP_PKEY_CTX_get_app_data((EVP_PKEY_CTX*)src_evp_pkey_ctx);
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
    if (app_data != NULL) {
        OPENSSL_free(app_data);
    }
}

static int pkey_signverify_init(EVP_PKEY_CTX* evp_pkey_ctx) {
    EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(evp_pkey_ctx);
    if (evp_pkey == NULL) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    if (EVP_PKEY_base_id(evp_pkey) == EVP_PKEY_DH) {
        ERROR("DH key type not allowed for signatures");
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

    pkey_key_data* key_data = EVP_PKEY_get0(evp_pkey);
    sa_header header;
    if (sa_key_header(&header, key_data->private_key) != SA_STATUS_OK) {
        ERROR("NULL evp_pkey");
        return 0;
    }

    sa_signature_algorithm signature_algorithm;
    sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
    sa_sign_parameters_rsa_pss parameters_rsa_pss;
    //    sa_sign_parameters_ecdsa parameters_ecdsa;
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
                parameters_rsa_pss.salt_length = app_data->pss_salt_length;
                parameters = &parameters_rsa_pss;
            } else {
                ERROR("Invalid padding mode");
                return 0;
            }

            break;

        case SA_KEY_TYPE_EC:
            signature_algorithm = SA_SIGNATURE_ALGORITHM_ECDSA;
            return 0;
            break;

        default:
            ERROR("Invalid key type");
            return 0;
    }

    if (sa_crypto_sign(signature, signature_length, signature_algorithm, key_data->private_key, data, data_length,
                parameters) != SA_STATUS_OK) {
        ERROR("sa_crypto_sign failed");
        return 0;
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
    EVP_PKEY_CTX* verify_pkey_ctx = NULL;
    do {
        verify_pkey_ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
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
    return result;
}

static int pkey_signverifyctx_init(
        EVP_PKEY_CTX* evp_pkey_ctx,
        EVP_MD_CTX* evp_md_ctx) {

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

    int key_type = EVP_PKEY_base_id(evp_pkey);
    if (key_type == EVP_PKEY_DH) {
        ERROR("DH key type not allowed for signatures");
        return 0;
    }

    app_data->evp_md_ctx = evp_md_ctx;
    return 1;
}

static int pkey_signctx(
        EVP_PKEY_CTX* evp_pkey_ctx,
        unsigned char* signature,
        size_t* signature_length,
        EVP_MD_CTX* evp_md_ctx) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    if (signature_length == NULL) {
        ERROR("NULL signature_length");
        return 0;
    }

    int result = 0;
    EVP_PKEY_CTX* temp_pkey_ctx = NULL;
    do {
        // Duplicate the EVP_PKEY_CTX because the EVP_DigestFinal will free it.
        temp_pkey_ctx = EVP_PKEY_CTX_dup(evp_pkey_ctx);
        if (temp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_dup failed");
            break;
        }

        unsigned int data_length = EVP_MD_CTX_size(evp_md_ctx);
        uint8_t data[data_length];
        if (signature != NULL) {
            if (EVP_DigestFinal(evp_md_ctx, data, &data_length) != 1) {
                ERROR("EVP_DigestFinal failed");
                break;
            }
        }

        result = pkey_sign(temp_pkey_ctx, signature, signature_length, data, data_length);
    } while (false);

    EVP_PKEY_CTX_free(temp_pkey_ctx);
    return result;
}

static int pkey_verifyctx(
        EVP_PKEY_CTX* evp_pkey_ctx,
        const unsigned char* signature,
        int signature_length,
        EVP_MD_CTX* evp_md_ctx) {

    if (evp_pkey_ctx == NULL) {
        ERROR("NULL evp_pkey_ctx");
        return 0;
    }

    if (evp_md_ctx == NULL) {
        ERROR("NULL evp_md_ctx");
        return 0;
    }

    if (signature == NULL) {
        ERROR("NULL signature");
        return 0;
    }

    int result = 0;
    EVP_PKEY_CTX* temp_pkey_ctx = NULL;
    do {
        // Duplicate the EVP_PKEY_CTX because the EVP_DigestFinal will free it.
        temp_pkey_ctx = EVP_PKEY_CTX_dup(evp_pkey_ctx);
        if (temp_pkey_ctx == NULL) {
            ERROR("EVP_PKEY_CTX_dup failed");
            break;
        }

        unsigned int data_length = EVP_MD_CTX_size(evp_md_ctx);
        uint8_t data[data_length];
        if (EVP_DigestFinal(evp_md_ctx, data, &data_length) != 1) {
            ERROR("EVP_DigestFinal failed");
            break;
        }

        result = pkey_verify(temp_pkey_ctx, signature, signature_length, data, data_length);
    } while (false);

    EVP_PKEY_CTX_free(temp_pkey_ctx);
    return result;
}

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
        case EVP_PKEY_CTRL_MD:
            app_data->evp_md = p2;
            if (app_data->evp_md_ctx != NULL) {
                // Keep the EVP_PKEY_CTX from being free'd in the DigestInit.
                EVP_MD_CTX_set_flags(app_data->evp_md_ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
                if (EVP_DigestInit(app_data->evp_md_ctx, p2) != 1) {
                    ERROR("EVP_DigestInit failed");
                    return 0;
                }

                // Put the original EVP_PKEY_CTX back int the EVP_MD_CTX and allow it to be freed again.
#if OPENSSL_VERSION_NUMBER >= 0x10100000
                EVP_MD_CTX_set_pkey_ctx(app_data->evp_md_ctx, evp_pkey_ctx);
#else
                app_data->evp_md_ctx->pctx = evp_pkey_ctx;
#endif
                EVP_MD_CTX_clear_flags(app_data->evp_md_ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
            }

            break;

        case EVP_PKEY_CTRL_RSA_PADDING:
            app_data->padding_mode = p1;
            break;

        case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
            app_data->pss_salt_length = p1;
            break;

        default:
            return 0;
    }

    return 1;
}

static int pkey_ctrl_str(
        EVP_PKEY_CTX* evp_pkey_ctx,
        const char* type,
        const char* value) {
    return 0;
}

static EVP_PKEY_METHOD* get_pkey_method(int nid) {
    EVP_PKEY_METHOD* evp_pkey_method = EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_AUTOARGLEN | EVP_PKEY_FLAG_SIGCTX_CUSTOM);
    if (evp_pkey_method != NULL) {
        EVP_PKEY_meth_set_init(evp_pkey_method, pkey_init);
        EVP_PKEY_meth_set_copy(evp_pkey_method, pkey_copy);
        EVP_PKEY_meth_set_cleanup(evp_pkey_method, pkey_cleanup);
        EVP_PKEY_meth_set_sign(evp_pkey_method, pkey_signverify_init, pkey_sign);
        EVP_PKEY_meth_set_verify(evp_pkey_method, pkey_signverify_init, pkey_verify);
        EVP_PKEY_meth_set_signctx(evp_pkey_method, pkey_signverifyctx_init, pkey_signctx);
        EVP_PKEY_meth_set_verifyctx(evp_pkey_method, pkey_signverifyctx_init, pkey_verifyctx);
        EVP_PKEY_meth_set_encrypt(evp_pkey_method, pkey_encrypt_init, pkey_encrypt);
        EVP_PKEY_meth_set_decrypt(evp_pkey_method, pkey_decrypt_init, pkey_decrypt);
        EVP_PKEY_meth_set_ctrl(evp_pkey_method, pkey_ctrl, pkey_ctrl_str);
    }

    return evp_pkey_method;
}

EVP_PKEY* sa_key_to_EVP_PKEY(sa_key key) {
    sa_header header;
    if (sa_key_header(&header, key) != SA_STATUS_OK) {
        ERROR("sa_key_header failed");
        return NULL;
    }

    size_t public_key_length;
    if (sa_key_get_public(NULL, &public_key_length, key) != SA_STATUS_OK) {
        ERROR("sa_key_get_public failed");
        return NULL;
    }

    EVP_PKEY* evp_pkey = NULL;
    uint8_t* public_key = NULL;
    pkey_key_data* key_data = NULL;
    do {
        public_key = OPENSSL_malloc(public_key_length);
        if (public_key == NULL) {
            ERROR("OPENSSL_malloc failed");
            break;
        }

        if (sa_key_get_public(public_key, &public_key_length, key) != SA_STATUS_OK) {
            ERROR("sa_key_get_public failed");
            break;
        }

        key_data = OPENSSL_malloc(sizeof(pkey_key_data));
        if (key_data == NULL) {
            ERROR("OPENSSL_malloc failed");
            break;
        }

        int type = 0;
        void* temp_key = NULL;
        switch (header.type) {
            case SA_KEY_TYPE_RSA: {
                type = EVP_PKEY_RSA;
                const uint8_t* p_public_key = public_key;
                temp_key = d2i_RSAPublicKey(NULL, &p_public_key, public_key_length);
                if (temp_key == NULL) {
                    ERROR("d2i_PublicKey failed");
                    break;
                }

                break;
            }

            default:
                break;
        }

        if (temp_key != NULL) {
            size_t temp_key_length = memory_size(temp_key, MAX_KEY_DATA_LEN);
            memcpy(key_data->data, temp_key, temp_key_length);

            // Free the original data structure, but don't free any of it's contents which are now pointed to by the
            // key_data.
            OPENSSL_free(temp_key);

            key_data->type = EVP_PKEY_SECAPI3;
            key_data->private_key = key;
            evp_pkey = EVP_PKEY_new();
            if (key_data == NULL) {
                ERROR("EVP_PKEY_new failed");
                break;
            }

            if (EVP_PKEY_assign(evp_pkey, type, key_data) != 1) {
                ERROR("EVP_PKEY_assign failed");
                EVP_PKEY_free(evp_pkey);
                break;
            }

            // Assigned to evp_pkey;
            key_data = NULL;
        }
    } while (false);

    if (public_key != NULL)
        OPENSSL_free(public_key);

    if (key_data != NULL)
        OPENSSL_free(public_key);

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
        if (rsa_pkey_method == NULL)
            rsa_pkey_method = get_pkey_method(EVP_PKEY_RSA);

        *method = rsa_pkey_method;
    } else if (nid == EVP_PKEY_EC) {
        if (ec_key_pkey_method == NULL)
            ec_key_pkey_method = get_pkey_method(EVP_PKEY_EC);

        *method = ec_key_pkey_method;
    } else if (nid == EVP_PKEY_DH) {
        if (dh_pkey_method == NULL)
            dh_pkey_method = get_pkey_method(EVP_PKEY_DH);

        *method = dh_pkey_method;
    } else {
        *method = NULL;
    }

    mtx_unlock(&engine_mutex);
    return *method == NULL ? 0 : 1;
}
