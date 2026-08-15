#pragma once

#include "crypto.hpp"
#include "fake_http.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <ctime>
#include <memory>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>

namespace syslocker::bedrock::test
{
    class SigningFixture
    {
    public:
        SigningFixture()
        {
            EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
            if (context == nullptr || EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_keygen(context, &key_) != 1)
            {
                if (context != nullptr)
                    EVP_PKEY_CTX_free(context);
                throw std::runtime_error("test Ed25519 key generation failed");
            }
            EVP_PKEY_CTX_free(context);

            std::array<unsigned char, 32> raw{};
            std::size_t length = raw.size();
            if (EVP_PKEY_get_raw_public_key(key_, raw.data(), &length) != 1 || length != raw.size())
                throw std::runtime_error("test public key export failed");
            publicKey = detail::base64UrlEncode(raw.data(), raw.size());
        }

        ~SigningFixture()
        {
            EVP_PKEY_free(key_);
        }

        SigningFixture(const SigningFixture &) = delete;
        SigningFixture &operator=(const SigningFixture &) = delete;

        HttpResponse signedResponse(const std::string &system,
                                    const std::string &challenge,
                                    std::string responseCode = "OK",
                                    bool authed = true,
                                    std::string token = "BRK_test-token",
                                    std::string identityField = {},
                                    std::string identityHash = {},
                                    std::string termination = {},
                                    std::int64_t serverTimeOffset = 0,
                                    std::optional<std::string> invisibleFolderToken = std::nullopt,
                                    std::map<std::string, std::optional<std::string>, std::less<>> variables = {}) const
        {
            nlohmann::json json{
                {"protocol_version", "bedrock-v1"},
                {"kid", "test-signing-key"},
                {"system", system},
                {"response_code", responseCode},
                {"human_response", responseCode == "OK" ? "Authentication successful." : "Request rejected."},
                {"is_error", responseCode != "OK" && responseCode != "MISSING_FIELD"},
                {"is_failure", responseCode == "MISSING_FIELD"},
                {"authed", authed},
                {"challenge", challenge},
                {"server_time", static_cast<std::int64_t>(std::time(nullptr)) + serverTimeOffset},
                {"human_time", "2026-08-09T00:00:00Z"},
            };
            if (!token.empty())
                json["session_token"] = token;
            if (!identityField.empty())
                json[identityField] = identityHash;
            if (!termination.empty())
                json["termination_message"] = termination;
            if (invisibleFolderToken)
                json["invisible_folder_token"] = *invisibleFolderToken;
            if (!variables.empty())
            {
                json["variables"] = nlohmann::json::object();
                for (const auto &[name, value] : variables)
                    json["variables"][name] = value ? nlohmann::json(*value) : nlohmann::json(false);
            }

            const std::string payload = json.dump();
            std::array<unsigned char, 64> signature{};
            std::size_t signatureLength = signature.size();
            EVP_MD_CTX *context = EVP_MD_CTX_new();
            if (context == nullptr || EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key_) != 1 ||
                EVP_DigestSign(context,
                               signature.data(),
                               &signatureLength,
                               reinterpret_cast<const unsigned char *>(payload.data()),
                               payload.size()) != 1 ||
                signatureLength != signature.size())
            {
                EVP_MD_CTX_free(context);
                throw std::runtime_error("test response signing failed");
            }
            EVP_MD_CTX_free(context);

            std::string combined(reinterpret_cast<const char *>(signature.data()), signature.size());
            combined += payload;
            HttpResponse response;
            response.status = 200;
            response.body = detail::base64UrlEncode(reinterpret_cast<const unsigned char *>(combined.data()), combined.size());
            response.headers["x-bedrock-protocol"] = "bedrock-v1";
            response.headers["x-bedrock-key-id"] = "test-signing-key";
            return response;
        }

        HttpResponse unsignedRevocation(const std::string &system,
                                        const std::string &challenge) const
        {
            nlohmann::json json{
                {"protocol_version", "bedrock-v1"},
                {"system", system},
                {"response_code", "SIGNING_KEY_REVOKED"},
                {"human_response", "This session is no longer valid."},
                {"is_error", true},
                {"is_failure", false},
                {"authed", false},
                {"challenge", challenge},
                {"server_time", static_cast<std::int64_t>(std::time(nullptr))},
                {"human_time", "2026-08-09T00:00:00Z"},
                {"termination_message", "This session is no longer valid."},
            };
            HttpResponse response;
            response.status = 200;
            response.body = json.dump();
            response.headers["x-bedrock-protocol"] = "bedrock-v1";
            response.headers["x-bedrock-signed"] = "false";
            return response;
        }

        std::string publicKey;

    private:
        EVP_PKEY *key_ = nullptr;
    };

    inline Config configFor(const SigningFixture &signer)
    {
        Config config;
        config.systemId = "bedrocksys0000000001";
        config.hwid = "TEST-HWID";
        config.version = "1.0.0";
        config.automaticHeartbeats = false;
        config.signingPublicKey = signer.publicKey;
        return config;
    }
}
