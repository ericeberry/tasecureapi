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

using namespace client_test_helpers;

TEST_P(SaEnginePkeyTest, rsaDigestSignWithUpdateFinalTest) {
    int nid = std::get<0>(GetParam());
    int padding = std::get<1>(GetParam());

    auto data = random(256);
    auto clear_key = sample_rsa_2048_pkcs8();
    sa_rights rights;
    rights_set_allow_all(&rights);
    auto key = create_sa_key_rsa(&rights, clear_key);
    std::vector<uint8_t> signature;

    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);
    ASSERT_NE(evp_md, nullptr);

    size_t length;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = NULL;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
    ASSERT_EQ(EVP_DigestSignUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), nullptr, &length), 1);
    signature.resize(length);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), signature.data(), &length), 1);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = NULL;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
TEST_P(SaEnginePkeyTest, rsaDigestSignNoUpdateFinalTest) {
    int nid = std::get<0>(GetParam());
    int padding = std::get<1>(GetParam());

    auto data = random(256);
    auto clear_key = sample_rsa_2048_pkcs8();
    sa_rights rights;
    rights_set_allow_all(&rights);
    auto key = create_sa_key_rsa(&rights, clear_key);
    std::vector<uint8_t> signature;

    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(sa_key_to_EVP_PKEY(*key), EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);
    ASSERT_NE(evp_md, nullptr);

    size_t length;

    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = NULL;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &length, data.data(), data.size()), 1);
    signature.resize(length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &length, data.data(), data.size()), 1);

    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = NULL;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}
#endif

TEST_P(SaEnginePkeyTest, rsaSignTest) {
    int nid = std::get<0>(GetParam());
    int padding = std::get<1>(GetParam());

    auto data = random(256);
    auto clear_key = sample_rsa_2048_pkcs8();
    sa_rights rights;
    rights_set_allow_all(&rights);
    auto key = create_sa_key_rsa(&rights, clear_key);
    std::vector<uint8_t> signature;

    std::shared_ptr<ENGINE> engine(sa_get_engine(), ENGINE_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);
    ASSERT_NE(evp_md, nullptr);
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

    size_t signature_length;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length), 1);

    // Verify with EVP_PKEY_verify
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
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = NULL;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsaTests,
        SaEnginePkeyTest,
        ::testing::Combine(
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING)));
