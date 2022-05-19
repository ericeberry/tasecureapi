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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_engine_common.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

using namespace client_test_helpers;

TEST_P(SaEnginePkeySignTest, digestSignWithUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    int nid = std::get<2>(GetParam());
    auto padding = std::get<3>(GetParam());
    auto salt = std::get<4>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);

    size_t signature_length = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestSignUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), nullptr, &signature_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), signature.data(), &signature_length), 1);
    signature.resize(signature_length);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaEnginePkeySignTest, signTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    int nid = std::get<2>(GetParam());
    auto padding = std::get<3>(GetParam());
    auto salt = std::get<4>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx.get(), salt), 1);
        }
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), salt), 1);
        }
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST(SaEnginePkeySignTest, defaultPaddingTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_sha256();
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    int padding = RSA_PKCS1_PADDING;
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST(SaEnginePkeySignTest, defaultSaltTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;
    int padding = RSA_PKCS1_PSS_PADDING;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_sha256();
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, RSA_PSS_SALTLEN_AUTO), 1);

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
TEST_P(SaEnginePkeySignTest, digestSignNoUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    int nid = std::get<2>(GetParam());
    auto padding = std::get<3>(GetParam());
    auto salt = std::get<4>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);

    size_t signature_length = 0;
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}

TEST_P(SaEnginePkeySignEdTest, digestSignTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);

    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), nullptr, nullptr, engine.get(), evp_pkey.get()), 1);
    size_t signature_length = 0;
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), nullptr, nullptr, engine.get(), evp_pkey.get()), 1);
    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}
#endif

TEST_P(SaEnginePkeyEncryptTest, encryptTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    auto padding = std::get<2>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);

    auto data = random(32);
    std::vector<uint8_t> encrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> encrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(encrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(encrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(encrypt_pkey_ctx.get(), padding), 1);
    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());
    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(decrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(decrypt_pkey_ctx.get(), padding), 1);
    size_t decrypted_data_length = 0;
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), nullptr, &decrypted_data_length, encrypted_data.data(),
            encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), decrypted_data.data(), &decrypted_data_length,
            encrypted_data.data(), encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    ASSERT_EQ(decrypted_data, data);
}

TEST_F(SaEnginePkeyEncryptTest, defaultPaddingTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;
    int padding = RSA_PKCS1_PADDING;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);

    auto data = random(32);
    std::vector<uint8_t> encrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> encrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(encrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(encrypt_pkey_ctx.get()), 1);
    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());
    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(decrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(decrypt_pkey_ctx.get(), padding), 1);
    size_t decrypted_data_length = 0;
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), nullptr, &decrypted_data_length, encrypted_data.data(),
            encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), decrypted_data.data(), &decrypted_data_length,
            encrypted_data.data(), encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    ASSERT_EQ(decrypted_data, data);
}

TEST_P(SaEnginePkeyDeriveTest, deriveTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);

    std::vector<uint8_t> clear_derived_key(SYM_128_KEY_SIZE);
    std::vector<uint8_t> clear_shared_secret;
    std::shared_ptr<EVP_PKEY> other_private_key;
    std::vector<uint8_t> other_public_key;
    if (key_type == SA_KEY_TYPE_DH) {
        std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> dh_parameters = get_dh_parameters(key_length);
        auto p = std::get<0>(dh_parameters);
        auto g = std::get<1>(dh_parameters);
        ASSERT_TRUE(dh_generate(other_private_key, other_public_key, p, g));
        ASSERT_TRUE(dh_compute_secret(clear_shared_secret, other_private_key, evp_pkey, p, g));
    } else if (key_type == SA_KEY_TYPE_EC) {
        ASSERT_EQ(ec_generate_key(curve, other_private_key, other_public_key), SA_STATUS_OK);
        ASSERT_TRUE(ecdh_compute_secret(curve, clear_shared_secret, other_private_key, evp_pkey));
    }

    auto info = random(AES_BLOCK_SIZE);
    ASSERT_TRUE(concat_kdf(clear_derived_key, clear_shared_secret, info, SA_DIGEST_ALGORITHM_SHA256));

    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_derive_init(evp_pkey_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_DH) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000
        // EVP_PKEY_CTX_set_dh_pad doesn't seem to work correctly in OpenSSL 3 with an engine.
        int result = EVP_PKEY_CTX_ctrl(evp_pkey_ctx.get(), EVP_PKEY_DH, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_PAD, 1,
                nullptr);
        ASSERT_EQ(result, 1);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000
        ASSERT_EQ(EVP_PKEY_CTX_set_dh_pad(evp_pkey_ctx.get(), 1), 1);
#endif
    }

    ASSERT_EQ(EVP_PKEY_derive_set_peer(evp_pkey_ctx.get(), other_private_key.get()), 1);
    size_t shared_secret_size = 0;
    ASSERT_EQ(EVP_PKEY_derive(evp_pkey_ctx.get(), nullptr, &shared_secret_size), 1);
    std::vector<uint8_t> shared_secret(shared_secret_size);
    size_t written = shared_secret_size;
    ASSERT_EQ(EVP_PKEY_derive(evp_pkey_ctx.get(), shared_secret.data(), &written), 1);

    sa_key shared_secret_key = *reinterpret_cast<sa_key*>(shared_secret.data());
    sa_kdf_parameters_concat kdf_parameters_concat = {
            .key_length = SYM_128_KEY_SIZE,
            .digest_algorithm = SA_DIGEST_ALGORITHM_SHA256,
            .parent = shared_secret_key,
            .info = info.data(),
            .info_length = info.size()};
    auto derived_key = create_uninitialized_sa_key();
    ASSERT_NE(derived_key, nullptr);
    sa_rights rights;
    rights_set_allow_all(&rights);
    sa_status status = sa_key_derive(derived_key.get(), &rights, SA_KDF_ALGORITHM_CONCAT, &kdf_parameters_concat);
    ASSERT_EQ(status, SA_STATUS_OK);
    ASSERT_TRUE(key_check_sym(*derived_key, clear_derived_key));
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyEdTests,
        SaEnginePkeySignEdTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_ED448)));
#endif

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsaPkcs1Tests,
        SaEnginePkeySignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH, RSA_4096_BYTE_LENGTH),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(RSA_PKCS1_PADDING),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsaPssTests,
        SaEnginePkeySignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH, RSA_4096_BYTE_LENGTH),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(RSA_PKCS1_PSS_PADDING),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyEcTests,
        SaEnginePkeySignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(0),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyEncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH, RSA_4096_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyDeriveDhTests,
        SaEnginePkeyDeriveTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_DH),
                ::testing::Values(DH_768_BYTE_LENGTH, DH_1024_BYTE_LENGTH, DH_1536_BYTE_LENGTH, DH_2048_BYTE_LENGTH, DH_3072_BYTE_LENGTH, DH_4096_BYTE_LENGTH)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyDeriveEcTests,
        SaEnginePkeyDeriveTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P256, SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521)));

#if OPENSSL_VERSION_NUMBER >= 0x10100000
INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyDeriveXTests,
        SaEnginePkeyDeriveTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_X448)));
#endif
