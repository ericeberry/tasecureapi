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

#include "sa_engine.h"
#include "sa_engine_internal.h"
#include "sa_log.h"
#include <openssl/engine.h>
#include <stdbool.h>
#include <string.h>
#include <threads.h>

#define SA_ENGINE_ID "secapi3"
#define SA_ENGINE_NAME "SecApi3 OpenSSL Engine"

mtx_t engine_mutex;
static once_flag flag = ONCE_FLAG_INIT;

static void sa_engine_shutdown() {
    ENGINE* engine = ENGINE_by_id(SA_ENGINE_ID);
    if (engine != NULL) {
        ENGINE_remove(engine);
        ENGINE_free(engine);
    }

    sa_free_engine_ciphers();
    mtx_destroy(&engine_mutex);
}

static void sa_engine_init() {
    if (mtx_init(&engine_mutex, mtx_plain | mtx_recursive) != thrd_success) {
        ERROR("mtx_init failed");
    }

    if (atexit(sa_engine_shutdown) != 0) {
        ERROR("atexit failed");
    }
}

ENGINE* sa_get_engine() {
    ENGINE* engine = NULL;

    call_once(&flag, sa_engine_init);

    if (mtx_lock(&engine_mutex) != 0) {
        ERROR("mtx_lock failed");
        return NULL;
    }

    engine = ENGINE_by_id(SA_ENGINE_ID);
    if (engine == NULL) {
        do {
            engine = ENGINE_new();
            if (engine == NULL) {
                ERROR("ENGINE_new failed");
                break;
            }

            if (!ENGINE_set_id(engine, SA_ENGINE_ID) ||
                    !ENGINE_set_name(engine, SA_ENGINE_NAME) ||
                    !ENGINE_set_ciphers(engine, sa_get_engine_ciphers) ||
                    !ENGINE_set_pkey_meths(engine, sa_get_engine_pkey_methods)) {
                ENGINE_free(engine);
                engine = NULL;
                ERROR("Engine init failed failed");
                break;
            }

            ENGINE_add(engine);
        } while (false);
    }

    mtx_unlock(&engine_mutex);
    return engine;
}
