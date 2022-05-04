/*
 * ============================================================================
 * COMCAST CONFIDENTIAL AND PROPRIETARY
 * ============================================================================
 * This file and its contents are the intellectual property of Comcast.  It may
 * not be used, copied, distributed or otherwise  disclosed in whole or in part
 * without the express written permission of Comcast.
 * ============================================================================
 * Copyright (c) 2022 Comcast. All rights reserved.
 * ============================================================================
 */

#include <openssl/engine.h>

static RSA_METHOD* rsa_method = NULL;

int secapi3_RSA_generate_key_ex(RSA* rsa, int bits, BIGNUM* e, BN_GENCB* cb) {
    return 1;
}

int secapi3_RSA_sign(int type, const unsigned char* m, unsigned int m_len,
        unsigned char* sigret, unsigned int* siglen, const RSA* rsa) {
    return 1;
}

int secapi3_RSA_verify(int type, const unsigned char* m, unsigned int m_len,
        const unsigned char* sigbuf, unsigned int siglen, const RSA* rsa) {
    return 1;
}

int secapi3_RSA_public_encrypt(int flen, const unsigned char* from,
        unsigned char* to, RSA* rsa, int padding) {
    return 1;
}

int secapi3_RSA_private_decrypt(int flen, const unsigned char* from,
        unsigned char* to, RSA* rsa, int padding) {
    return 1;
}

int secapi3_RSA_finish(RSA* rsa) {
    return 1;
}

RSA_METHOD* getRsaMethod() {
    if (rsa_method == NULL) {
        rsa_method = RSA_meth_new("secapi3 RSA", RSA_METHOD_FLAG_NO_CHECK);
        if (rsa_method == NULL) {
            fprintf(stderr, "RSA_meth_new failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }

        if (RSA_meth_set_sign(rsa_method, secapi3_RSA_sign) != 1) {
            fprintf(stderr, "RSA_meth_set_sign failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }

        if (RSA_meth_set_verify(rsa_method, secapi3_RSA_verify) != 1) {
            fprintf(stderr, "RSA_meth_set_verify failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }

        if (RSA_meth_set_pub_enc(rsa_method, secapi3_RSA_public_encrypt) != 1) {
            fprintf(stderr, "RSA_meth_set_pub_enc failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }

        if (RSA_meth_set_priv_enc(rsa_method, secapi3_RSA_private_decrypt) != 1) {
            fprintf(stderr, "RSA_meth_set_priv_enc failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }

        if (RSA_meth_set_keygen(rsa_method, secapi3_RSA_generate_key_ex) != 1) {
            fprintf(stderr, "RSA_meth_set_keygen failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }

        if (RSA_meth_set_finish(rsa_method, secapi3_RSA_finish) != 1) {
            fprintf(stderr, "RSA_meth_set_finish failed\n");
            RSA_meth_free(rsa_method);
            return NULL;
        }
    }

    return NULL;
}
