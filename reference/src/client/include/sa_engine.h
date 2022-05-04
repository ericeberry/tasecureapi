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

/**
 * @file SecApi3Engine.h
 *
 * SecApi3Engine implements an OpenSSL Engine that delegates its implementation to SecApi 3. Users can use the OpenSSL
 * API, but SecApi3 will be used to perform the cryptographic processing.
 *
 * To use an engine, users must call sa_engine_new(). This will create the engine an instance of it. User will submit
 * the Engine as the impl parameter in calls like EVP_EncryptInit_ex and EVP_SignInit_ex. Once finished with the Engine,
 * users must call sa_engine_free. APIs that take an unsigned char* key parameter with a pointer to the sa_key value
 * identifying the SecApi 3 key.
 */

#ifndef SA_ENGINE_H
#define SA_ENGINE_H

#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes a SecApi3 Engine and returns an instance of it.
 *
 * @return 1 if successful and 0 if not.
 */
ENGINE* sa_engine_new();

/**
 * Frees an SecApi3 Engine instance.
 *
 * @param[in] engine the instance to free.
 */
void sa_engine_free(ENGINE* engine);

#ifdef __cplusplus
}
#endif

#endif //SA_ENGINE_H
