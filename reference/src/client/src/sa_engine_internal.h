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

#ifndef SA_ENGINE_INTERNAL_H
#define SA_ENGINE_INTERNAL_H

#include "sa.h"
#include "sa_common.h"
#include <openssl/engine.h>
#include <threads.h>

#ifdef __cplusplus
extern "C" {
#endif

// These do not follow the convention of all upper case to make the DECLARE_CIPHER macro work properly.
#define BLOCK_SIZE_aes_cbc 16
#define BLOCK_SIZE_aes_ecb 16
#define BLOCK_SIZE_aes_ctr 1
#define BLOCK_SIZE_aes_gcm 1
#define BLOCK_SIZE_chacha20_chacha20 1
#define BLOCK_SIZE_chacha20_poly1305 1
#define IV_LEN_aes_cbc 16
#define IV_LEN_aes_ecb 0
#define IV_LEN_aes_ctr 16
#define IV_LEN_aes_gcm 12
#define IV_LEN_chacha20_chacha20 16
#define IV_LEN_chacha20_poly1305 12
#define NID_chacha20_256_chacha20 NID_chacha20
#define NID_chacha20_256_poly1305 NID_chacha20_poly1305

extern mtx_t engine_mutex;

/**
 * Returns a cipher for the SecApi3 Engine as requested by nid. If the ciphers parameter is NULL, returns the list of
 * nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] cipher the cipher referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if cipher is NULL.
 * @param[in] nid the nid for which to return the cipher.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_ciphers(
        ENGINE* e,
        const EVP_CIPHER** cipher,
        const int** nids,
        int nid);

/**
 * Frees all of the created ciphers.
 */
void sa_free_engine_ciphers();

/**
 * Returns a digest for the SecApi3 Engine as requested by nid. If the digests parameter is NULL, returns the list of
 * nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] evp_md the digest referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if evp_md is NULL.
 * @param[in] nid the nid for which to return the digest.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_digests(
        ENGINE* engine,
        const EVP_MD** evp_md,
        const int** nids,
        int nid);

/**
 * Frees all of the created digests.
 */
void sa_free_engine_digests();

/**
 * Returns a pkey method for the SecApi3 Engine as requested by nid. If the method parameter is NULL, returns the list
 * of nids supported by this engine.
 *
 * @param[in] engine the engine instance.
 * @param[out] method the pkey method referenced by the nid.
 * @param[out] nids the list of nids supported by this engine if method is NULL.
 * @param[in] nid the nid for which to return the pkey method.
 * @return 1 if successful and 0 if not.
 */
int sa_get_engine_pkey_methods(
        ENGINE* engine,
        EVP_PKEY_METHOD** method,
        const int** nids,
        int nid);

#ifdef __cplusplus
}
#endif

#endif //SA_ENGINE_INTERNAL_H
