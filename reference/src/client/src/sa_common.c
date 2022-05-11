/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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

#include "sa_common.h"
#include "sa.h"
#include "sa_log.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <memory.h>
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000
#include <openssl/ecdsa.h>
#endif

EVP_PKEY* rsa_import_public(
        const uint8_t* in,
        size_t in_length) {

    const uint8_t* p = in;
    EVP_PKEY* evp_pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, in_length);
    if (evp_pkey == NULL) {
        ERROR("d2i_PublicKey failed");
        return NULL;
    }

    return evp_pkey;
}

bool is_pcurve(sa_elliptic_curve curve) {
    return curve == SA_ELLIPTIC_CURVE_NIST_P256 || curve == SA_ELLIPTIC_CURVE_NIST_P384 ||
           curve == SA_ELLIPTIC_CURVE_NIST_P521;
}

size_t ec_get_key_size(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P256:
            return EC_P256_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return EC_P384_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return EC_P521_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_ED25519:
        case SA_ELLIPTIC_CURVE_X25519:
            return EC_25519_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_ED448:
            return EC_ED448_KEY_SIZE;

        case SA_ELLIPTIC_CURVE_X448:
            return EC_X448_KEY_SIZE;

        default:
            return 0;
    }
}

int ec_get_type(sa_elliptic_curve curve) {
    switch (curve) {
        case SA_ELLIPTIC_CURVE_NIST_P256:
            return NID_X9_62_prime256v1;

        case SA_ELLIPTIC_CURVE_NIST_P384:
            return NID_secp384r1;

        case SA_ELLIPTIC_CURVE_NIST_P521:
            return NID_secp521r1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        case SA_ELLIPTIC_CURVE_ED25519:
            return NID_ED25519;

        case SA_ELLIPTIC_CURVE_X25519:
            return NID_X25519;

        case SA_ELLIPTIC_CURVE_ED448:
            return NID_ED448;

        case SA_ELLIPTIC_CURVE_X448:
            return NID_X448;
#endif

        default:
            ERROR("Unknown EC curve encountered");
            return 0;
    }
}

EVP_PKEY* ec_import_public(
        sa_elliptic_curve curve,
        const uint8_t* in,
        size_t in_length) {

    EC_POINT* ec_point = NULL;
    EC_GROUP* ec_group = NULL;
    EC_KEY* ec_key = NULL;
    EVP_PKEY* evp_pkey = NULL;
    do {
        int type = ec_get_type(curve);
        ec_group = EC_GROUP_new_by_curve_name(type);
        if (ec_group != NULL) {
            uint8_t public_key[in_length + 1];
            public_key[0] = POINT_CONVERSION_UNCOMPRESSED;
            memcpy(public_key + 1, in, in_length);

            ec_point = EC_POINT_new(ec_group);
            if (ec_point == NULL) {
                ERROR("EC_POINT_new failed");
                break;
            }

            if (EC_POINT_oct2point(ec_group, ec_point, public_key, sizeof(public_key), NULL) != 1) {
                ERROR("EC_POINT_oct2point failed");
                break;
            }

            ec_key = EC_KEY_new_by_curve_name(type);
            if (ec_key == NULL) {
                ERROR("EC_KEY_new failed");
                break;
            }

            if (EC_KEY_set_public_key(ec_key, ec_point) != 1) {
                ERROR("EC_KEY_set_public_key failed");
                break;
            }

            evp_pkey = EVP_PKEY_new();
            if (evp_pkey == NULL) {
                ERROR("EVP_PKEY_new failed");
                break;
            }

            if (EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key) != 1) {
                ERROR("EVP_PKEY_set1_EC_KEY failed");
                EVP_PKEY_free(evp_pkey);
                break;
            }
        }
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        else if (curve == SA_ELLIPTIC_CURVE_ED25519 || curve == SA_ELLIPTIC_CURVE_ED448 ||
                 curve == SA_ELLIPTIC_CURVE_X25519 || curve == SA_ELLIPTIC_CURVE_X448) {
            evp_pkey = EVP_PKEY_new_raw_public_key(type, NULL, in, in_length);
            if (evp_pkey == NULL) {
                ERROR("EVP_PKEY_new failed");
                break;
            }
        }
#endif
    } while (false);

    EC_POINT_free(ec_point);
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_key);

    return evp_pkey;
}

bool ec_encode_signature(
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    bool result = false;
    ECDSA_SIG* ecdsa_signature = NULL;
    BIGNUM* bn_r = NULL;
    BIGNUM* bn_s = NULL;
    do {
        ecdsa_signature = ECDSA_SIG_new();
        if (ecdsa_signature == NULL) {
            ERROR("ECDSA_SIG_new failed");
            break;
        }

        bn_r = BN_bin2bn(in, in_length / 2, NULL);
        if (bn_r == NULL) {
            ERROR("BN_bin2bn failed");
            break;
        }

        bn_s = BN_bin2bn(in + in_length / 2, in_length / 2, NULL);
        if (bn_s == NULL) {
            ERROR("BN_bin2bn failed");
            break;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        BN_swap(ecdsa_signature->r, bn_r);
        BN_swap(ecdsa_signature->s, bn_s);
#else
        ECDSA_SIG_set0(ecdsa_signature, bn_r, bn_s);

        // ownership transferred to ecdsa_signature
        bn_r = NULL;
        bn_s = NULL;
#endif
        uint8_t* p_out = out;
        *out_length = i2d_ECDSA_SIG(ecdsa_signature, &p_out);
        if (*out_length == 0) {
            ERROR("i2d_ECDSA_SIG failed");
            break;
        }

        result = true;
    } while (false);

    BN_free(bn_r);
    BN_free(bn_s);
    ECDSA_SIG_free(ecdsa_signature);
    return result;
}

EVP_PKEY* get_public_key(sa_key key) {
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

        switch (header.type) {
            case SA_KEY_TYPE_RSA:
                evp_pkey = rsa_import_public(public_key, public_key_length);
                if (evp_pkey == NULL) {
                    ERROR("rsa_import_public failed");
                    continue;
                }

                break;

            case SA_KEY_TYPE_EC:
                evp_pkey = ec_import_public(header.param, public_key, public_key_length);
                if (evp_pkey == NULL) {
                    ERROR("ec_import_public failed");
                    continue;
                }

                break;

            default:
                continue;
        }
    } while (false);

    if (public_key != NULL)
        OPENSSL_free(public_key);

    return evp_pkey;
}
