#include "crypto.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace syslocker::bedrock::detail
{
    namespace
    {
        constexpr std::size_t kSignatureBytes = 64;
        constexpr std::size_t kPublicKeyBytes = 32;
        constexpr std::size_t kChallengeBytes = 64;
        constexpr std::size_t kMaximumTransportBytes = 1024 * 1024;
        constexpr std::string_view kProtocol = "bedrock-v1";

        using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

        bool validBase64UrlCharacter(unsigned char value)
        {
            return (value >= 'A' && value <= 'Z') ||
                   (value >= 'a' && value <= 'z') ||
                   (value >= '0' && value <= '9') || value == '-' || value == '_';
        }

        bool expectedAuthenticated(ResponseCode code)
        {
            return code == ResponseCode::Ok || code == ResponseCode::Outdated;
        }

        bool expectedFailure(ResponseCode code)
        {
            switch (code)
            {
            case ResponseCode::MissingField:
            case ResponseCode::InvalidRequest:
            case ResponseCode::InvalidSystem:
            case ResponseCode::SystemPaused:
            case ResponseCode::PlanInactive:
            case ResponseCode::ProductionAuthUnavailable:
            case ResponseCode::ProgramDigestMismatch:
            case ResponseCode::InvalidBeatRate:
            case ResponseCode::NoActiveSigningKey:
            case ResponseCode::InternalError:
                return true;
            default:
                return false;
            }
        }

        bool expectedError(ResponseCode code)
        {
            return code != ResponseCode::Ok && !expectedFailure(code);
        }

        Result<Response> parsePayload(const Config &config,
                                      std::string jsonBytes,
                                      std::string_view expectedChallenge)
        {
            try
            {
                const auto json = nlohmann::json::parse(jsonBytes);
                if (!json.is_object())
                    return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock payload is not a JSON object.");

                auto requiredString = [&json](const char *name) -> std::string
                {
                    if (!json.contains(name) || !json.at(name).is_string())
                        throw std::runtime_error(std::string("Bedrock field '") + name + "' is missing or has the wrong type.");
                    return json.at(name).get<std::string>();
                };
                auto requiredBool = [&json](const char *name) -> bool
                {
                    if (!json.contains(name) || !json.at(name).is_boolean())
                        throw std::runtime_error(std::string("Bedrock field '") + name + "' is missing or has the wrong type.");
                    return json.at(name).get<bool>();
                };

                Response response;
                response.protocolVersion = requiredString("protocol_version");
                response.system = requiredString("system");
                response.responseCode = requiredString("response_code");
                response.code = responseCodeFromString(response.responseCode);
                response.humanResponse = requiredString("human_response");
                response.isError = requiredBool("is_error");
                response.isFailure = requiredBool("is_failure");
                response.authed = requiredBool("authed");
                response.humanTime = requiredString("human_time");

                if (!json.contains("server_time") || !json.at("server_time").is_number_integer())
                    throw std::runtime_error("Bedrock field 'server_time' is missing or has the wrong type.");
                response.serverTime = json.at("server_time").get<std::int64_t>();

                if (!json.contains("challenge") || !json.at("challenge").is_string())
                    throw std::runtime_error("Bedrock response did not echo a valid challenge.");
                response.challenge = json.at("challenge").get<std::string>();

                auto optionalString = [&json](const char *name) -> std::optional<std::string>
                {
                    if (!json.contains(name) || json.at(name).is_null())
                        return std::nullopt;
                    if (!json.at(name).is_string())
                        throw std::runtime_error(std::string("Bedrock field '") + name + "' has the wrong type.");
                    return json.at(name).get<std::string>();
                };

                response.keyId = optionalString("kid");
                response.sessionToken = optionalString("session_token");
                response.licenseKeyHash = optionalString("license_key_hash");
                response.usernameHash = optionalString("username_hash");
                response.terminationMessage = optionalString("termination_message");
                response.invisibleFolderToken = optionalString("invisible_folder_token");

                if (json.contains("variables"))
                {
                    const auto &variables = json.at("variables");
                    if (!variables.is_object())
                        throw std::runtime_error("Bedrock field 'variables' has the wrong type.");
                    for (auto it = variables.begin(); it != variables.end(); ++it)
                    {
                        if (it.value().is_boolean() && !it.value().get<bool>())
                            response.variables.emplace(it.key(), std::nullopt);
                        else if (it.value().is_string())
                            response.variables.emplace(it.key(), it.value().get<std::string>());
                        else
                            throw std::runtime_error("Bedrock variable has the wrong type.");
                    }
                }

                if (response.protocolVersion != kProtocol)
                    return Result<Response>::fail(ErrorKind::InvalidPayload, "Unsupported Bedrock protocol version.");
                if (response.code == ResponseCode::Unknown)
                    return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock response contains an unknown response code.");
                if (response.authed != expectedAuthenticated(response.code) ||
                    response.isError != expectedError(response.code) ||
                    response.isFailure != expectedFailure(response.code))
                    return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock response flags contradict its response code.");
                if (response.system != config.systemId)
                    return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock response is bound to a different system.");
                if (response.challenge != expectedChallenge)
                    return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock response challenge does not match the request.");
                const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                const auto difference = response.serverTime > static_cast<std::int64_t>(now)
                                            ? response.serverTime - static_cast<std::int64_t>(now)
                                            : static_cast<std::int64_t>(now) - response.serverTime;
                if (difference > config.maxServerClockSkew.count())
                    return Result<Response>::fail(ErrorKind::FreshnessViolation, "Bedrock response server time is outside the configured freshness window.");

                return response;
            }
            catch (const nlohmann::json::exception &error)
            {
                return Result<Response>::fail(ErrorKind::InvalidPayload,
                                              std::string("Bedrock response JSON is invalid: ") + error.what());
            }
            catch (const std::exception &error)
            {
                return Result<Response>::fail(ErrorKind::InvalidPayload, error.what());
            }
        }
    }

    Result<std::vector<unsigned char>> base64UrlDecode(std::string_view value)
    {
        if (value.empty() || value.size() > kMaximumTransportBytes || value.size() % 4 == 1)
            return Result<std::vector<unsigned char>>::fail(ErrorKind::InvalidPayload, "Invalid base64url length.");

        for (const unsigned char character : value)
        {
            if (!validBase64UrlCharacter(character))
                return Result<std::vector<unsigned char>>::fail(ErrorKind::InvalidPayload, "Invalid base64url character.");
        }

        std::string base64(value);
        for (char &character : base64)
        {
            if (character == '-')
                character = '+';
            else if (character == '_')
                character = '/';
        }
        base64.append((4 - base64.size() % 4) % 4, '=');

        std::vector<unsigned char> decoded((base64.size() / 4) * 3);
        const int length = EVP_DecodeBlock(decoded.data(),
                                           reinterpret_cast<const unsigned char *>(base64.data()),
                                           static_cast<int>(base64.size()));
        if (length < 0)
            return Result<std::vector<unsigned char>>::fail(ErrorKind::InvalidPayload, "Invalid base64url value.");

        std::size_t padding = 0;
        if (!base64.empty() && base64.back() == '=')
            ++padding;
        if (base64.size() > 1 && base64[base64.size() - 2] == '=')
            ++padding;
        decoded.resize(static_cast<std::size_t>(length) - padding);
        return decoded;
    }

    std::string base64UrlEncode(const unsigned char *bytes, std::size_t length)
    {
        std::string encoded(4 * ((length + 2) / 3), '\0');
        const int outputLength = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(encoded.data()),
                                                 bytes,
                                                 static_cast<int>(length));
        encoded.resize(static_cast<std::size_t>(outputLength));
        for (char &character : encoded)
        {
            if (character == '+')
                character = '-';
            else if (character == '/')
                character = '_';
        }
        while (!encoded.empty() && encoded.back() == '=')
            encoded.pop_back();
        return encoded;
    }

    Result<std::string> generateChallenge()
    {
        std::array<unsigned char, kChallengeBytes> random{};
        if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
            return Result<std::string>::fail(ErrorKind::LocalFailure, "A cryptographically secure Bedrock challenge could not be generated.");
        return base64UrlEncode(random.data(), random.size());
    }

    Result<std::string> sha256Hex(std::string_view value)
    {
        MdCtxPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(context.get(), value.data(), value.size()) != 1)
            return Result<std::string>::fail(ErrorKind::LocalFailure, "SHA-256 initialization failed.");

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int length = 0;
        if (EVP_DigestFinal_ex(context.get(), digest.data(), &length) != 1 || length != 32)
            return Result<std::string>::fail(ErrorKind::LocalFailure, "SHA-256 calculation failed.");

        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (unsigned int index = 0; index < length; ++index)
            output << std::setw(2) << static_cast<unsigned int>(digest[index]);
        return output.str();
    }

    Result<Response> verifySignedResponse(const Config &config,
                                          const HttpResponse &httpResponse,
                                          std::string_view expectedChallenge)
    {
        const std::string protocol = httpResponse.header("x-bedrock-protocol");
        if (protocol != kProtocol || httpResponse.header("x-bedrock-signed") == "false")
            return Result<Response>::fail(ErrorKind::UnsignedResponse, "Bedrock response is missing its signed transport headers.");

        auto signedBytes = base64UrlDecode(httpResponse.body);
        if (!signedBytes || signedBytes->size() <= kSignatureBytes)
            return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock signed response has an invalid encoding or length.");

        auto publicKey = base64UrlDecode(config.signingPublicKey);
        if (!publicKey || publicKey->size() != kPublicKeyBytes)
            return Result<Response>::fail(ErrorKind::Configuration, "Pinned Bedrock public key is not a raw 32-byte Ed25519 key.");

        PkeyPtr key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
                                                nullptr,
                                                publicKey->data(),
                                                publicKey->size()),
                    &EVP_PKEY_free);
        MdCtxPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!key || !context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1)
            return Result<Response>::fail(ErrorKind::LocalFailure, "Ed25519 verifier initialization failed.");

        const unsigned char *signature = signedBytes->data();
        const unsigned char *message = signedBytes->data() + kSignatureBytes;
        const std::size_t messageLength = signedBytes->size() - kSignatureBytes;
        if (EVP_DigestVerify(context.get(), signature, kSignatureBytes, message, messageLength) != 1)
            return Result<Response>::fail(ErrorKind::InvalidSignature, "Bedrock response signature verification failed.");

        auto parsed = parsePayload(config,
                                   std::string(reinterpret_cast<const char *>(message), messageLength),
                                   expectedChallenge);
        if (!parsed)
            return parsed;
        if (!parsed->keyId || httpResponse.header("x-bedrock-key-id") != *parsed->keyId)
            return Result<Response>::fail(ErrorKind::InvalidPayload, "Bedrock response signing key ID is missing or inconsistent.");
        return parsed;
    }

    Result<Response> parseUnsignedRevocation(const Config &config,
                                             const HttpResponse &httpResponse,
                                             std::string_view expectedChallenge)
    {
        if (httpResponse.header("x-bedrock-signed") != "false" ||
            httpResponse.header("x-bedrock-protocol") != kProtocol)
            return Result<Response>::fail(ErrorKind::UnsignedResponse, "Bedrock returned an unauthenticated response.");

        auto parsed = parsePayload(config, httpResponse.body, expectedChallenge);
        if (!parsed)
            return parsed;
        if (parsed->code != ResponseCode::SigningKeyRevoked || !parsed->terminationMessage)
            return Result<Response>::fail(ErrorKind::UnsignedResponse, "Unsigned Bedrock response is diagnostic only and cannot be trusted.");

        // This narrow denial-only exception is part of the Bedrock protocol.
        // It never grants access and is used only when the pinned server key
        // row was deleted before a terminal response could be signed.
        return parsed;
    }
}
