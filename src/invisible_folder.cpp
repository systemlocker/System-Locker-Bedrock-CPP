#include "syslocker/bedrock/invisible_folder.hpp"

#include "syslocker/bedrock/http.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>

namespace syslocker::bedrock
{
    namespace
    {
        constexpr std::string_view kDownloadPrefix = "/a/";
        constexpr std::string_view kMetadataPrefix = "/api/v1/files/";
        constexpr std::string_view kMetadataSuffix = "/metadata";

        std::string endpoint(const std::string &baseUrl, std::string_view path)
        {
            if (!baseUrl.empty() && baseUrl.back() == '/')
                return baseUrl.substr(0, baseUrl.size() - 1) + std::string(path);
            return baseUrl + std::string(path);
        }

        bool validReferenceId(std::string_view value)
        {
            return value.size() >= 4 && value.size() <= 128 &&
                   std::all_of(value.begin(), value.end(), [](unsigned char character)
                               {
                                   return std::isalnum(character) || character == '_' || character == '-';
                               });
        }

        std::string percentEncode(std::string_view value)
        {
            constexpr char hex[] = "0123456789ABCDEF";
            std::string encoded;
            for (unsigned char character : value)
            {
                if (std::isalnum(character) || character == '-' || character == '_' || character == '.')
                    encoded.push_back(static_cast<char>(character));
                else
                {
                    encoded.push_back('%');
                    encoded.push_back(hex[character >> 4]);
                    encoded.push_back(hex[character & 0x0F]);
                }
            }
            return encoded;
        }

        Error transportError(std::string_view action, const HttpResponse &response)
        {
            if (!response.error.empty())
                return {ErrorKind::Transport, std::string("Invisible Folder ") + std::string(action) + " failed: " + response.error};
            return {ErrorKind::Transport, std::string("Invisible Folder ") + std::string(action) + " returned HTTP " + std::to_string(response.status) + "."};
        }

        std::string errorMessage(const HttpResponse &response)
        {
            try
            {
                const auto json = nlohmann::json::parse(response.body);
                if (json.contains("message") && json.at("message").is_string())
                    return json.at("message").get<std::string>();
                if (json.contains("error") && json.at("error").is_string())
                    return json.at("error").get<std::string>();
            }
            catch (const nlohmann::json::exception &)
            {
            }
            return {};
        }

        Result<InvisibleFolderMetadata> parseMetadata(const HttpResponse &response)
        {
            try
            {
                const auto json = nlohmann::json::parse(response.body);
                if (!json.contains("data") || !json.at("data").is_object())
                    throw std::runtime_error("Invisible Folder metadata response has no data object.");
                const auto &data = json.at("data");
                if (!data.contains("file") || !data.at("file").is_object() ||
                    !data.contains("metadata") || !data.at("metadata").is_object())
                    throw std::runtime_error("Invisible Folder metadata response has the wrong shape.");

                const auto &file = data.at("file");
                auto stringField = [&file](const char *name) -> std::string
                {
                    if (!file.contains(name) || !file.at(name).is_string())
                        throw std::runtime_error(std::string("Invisible Folder file field '") + name + "' has the wrong type.");
                    return file.at(name).get<std::string>();
                };
                auto unsignedField = [&file](const char *name) -> std::uint64_t
                {
                    if (!file.contains(name) || !file.at(name).is_number_unsigned())
                        throw std::runtime_error(std::string("Invisible Folder file field '") + name + "' has the wrong type.");
                    return file.at(name).get<std::uint64_t>();
                };
                auto signedField = [&file](const char *name) -> std::int64_t
                {
                    if (!file.contains(name) || !file.at(name).is_number_integer())
                        throw std::runtime_error(std::string("Invisible Folder file field '") + name + "' has the wrong type.");
                    return file.at(name).get<std::int64_t>();
                };

                InvisibleFolderMetadata parsed;
                parsed.file = {
                    stringField("id"), stringField("reference_id"), stringField("name"), stringField("mime_type"),
                    unsignedField("size"), unsignedField("downloads"), stringField("uploaded_at"), signedField("permission_type_id")};

                for (auto it = data.at("metadata").begin(); it != data.at("metadata").end(); ++it)
                {
                    if (!it.value().is_object() || !it.value().contains("value") || !it.value().at("value").is_string())
                        throw std::runtime_error("Invisible Folder metadata entry has the wrong type.");
                    InvisibleFolderMetadataValue value{it.value().at("value").get<std::string>(), std::nullopt};
                    if (it.value().contains("created_at") && !it.value().at("created_at").is_null())
                    {
                        if (!it.value().at("created_at").is_string())
                            throw std::runtime_error("Invisible Folder metadata creation time has the wrong type.");
                        value.createdAt = it.value().at("created_at").get<std::string>();
                    }
                    parsed.values.emplace(it.key(), std::move(value));
                }
                return parsed;
            }
            catch (const nlohmann::json::exception &error)
            {
                return Result<InvisibleFolderMetadata>::fail(ErrorKind::InvalidPayload,
                                                             std::string("Invisible Folder metadata JSON is invalid: ") + error.what());
            }
            catch (const std::exception &error)
            {
                return Result<InvisibleFolderMetadata>::fail(ErrorKind::InvalidPayload, error.what());
            }
        }
    }

    InvisibleFolder::InvisibleFolder(IHttpClient &http, const Config &config) : http_(http), config_(config) {}

    bool InvisibleFolder::hasToken() const noexcept
    {
        std::lock_guard lock(mutex_);
        return !token_.empty();
    }

    Result<std::vector<std::uint8_t>> InvisibleFolder::download(std::string_view referenceId) const
    {
        if (!config_.invisibleFolderBaseUrl.starts_with("https://"))
            return Result<std::vector<std::uint8_t>>::fail(ErrorKind::Configuration, "Invisible Folder base URL must use HTTPS.");
        if (!validReferenceId(referenceId))
            return Result<std::vector<std::uint8_t>>::fail(ErrorKind::Configuration, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.");

        std::string token;
        {
            std::lock_guard lock(mutex_);
            token = token_;
        }
        if (token.empty())
            return Result<std::vector<std::uint8_t>>::fail(ErrorKind::SessionTerminated,
                                                            "No Invisible Folder token is available. Request one during initialization or a heartbeat.");

        const HttpResponse response = http_.post(endpoint(config_.invisibleFolderBaseUrl, kDownloadPrefix) + std::string(referenceId),
                                                  {{"invisiblefolder_token", token}});
        std::fill(token.begin(), token.end(), '\0');
        if (!response.ok())
        {
            const std::string message = errorMessage(response);
            return Result<std::vector<std::uint8_t>>::fail(
                ErrorKind::Transport,
                message.empty() ? transportError("download", response).message : "Invisible Folder download failed: " + message);
        }
        return std::vector<std::uint8_t>(response.body.begin(), response.body.end());
    }

    Result<void *> InvisibleFolder::downloadToFile(std::string_view referenceId,
                                                    const std::filesystem::path &destination) const
    {
        if (destination.empty())
            return Result<void *>::fail(ErrorKind::Configuration, "Invisible Folder download destination cannot be empty.");
        const auto bytes = download(referenceId);
        if (!bytes)
            return Result<void *>::fail(bytes.error().kind, bytes.error().message);

        std::ofstream output(destination, std::ios::binary | std::ios::trunc);
        if (!output)
            return Result<void *>::fail(ErrorKind::LocalFailure, "Could not open Invisible Folder download destination.");
        output.write(reinterpret_cast<const char *>(bytes->data()), static_cast<std::streamsize>(bytes->size()));
        if (!output)
            return Result<void *>::fail(ErrorKind::LocalFailure, "Could not write Invisible Folder download destination.");
        return static_cast<void *>(nullptr);
    }

    Result<InvisibleFolderMetadata> InvisibleFolder::metadata(std::string_view referenceId,
                                                               const std::vector<std::string> &keys) const
    {
        if (!config_.invisibleFolderBaseUrl.starts_with("https://"))
            return Result<InvisibleFolderMetadata>::fail(ErrorKind::Configuration, "Invisible Folder base URL must use HTTPS.");
        if (!validReferenceId(referenceId))
            return Result<InvisibleFolderMetadata>::fail(ErrorKind::Configuration, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.");

        HttpHeaders headers;
        if (config_.invisibleFolderApiKey && !config_.invisibleFolderApiKey->empty())
            headers.emplace_back("X-Api-Key", *config_.invisibleFolderApiKey);
        {
            std::lock_guard lock(mutex_);
            if (!token_.empty())
                headers.emplace_back("X-Invisiblefolder-Token", token_);
        }

        std::string url = endpoint(config_.invisibleFolderBaseUrl, kMetadataPrefix) + std::string(referenceId) + std::string(kMetadataSuffix);
        for (const auto &key : keys)
            url += (url.find('?') == std::string::npos ? "?keys[]=" : "&keys[]=") + percentEncode(key);

        const HttpResponse response = http_.get(url, headers);
        if (!response.ok())
        {
            const std::string message = errorMessage(response);
            return Result<InvisibleFolderMetadata>::fail(
                ErrorKind::Transport,
                message.empty() ? transportError("metadata request", response).message : "Invisible Folder metadata request failed: " + message);
        }
        return parseMetadata(response);
    }

    Result<DownloadIfNewResult> InvisibleFolder::downloadIfNew(
        std::string_view referenceId,
        std::optional<std::string_view> knownRevision,
        std::optional<std::filesystem::path> destination) const
    {
        const auto currentMetadata = metadata(referenceId, {"__revisions"});
        if (!currentMetadata)
            return Result<DownloadIfNewResult>::fail(currentMetadata.error().kind, currentMetadata.error().message);

        const auto revision = currentMetadata->values.find("__revisions");
        if (revision == currentMetadata->values.end())
            return Result<DownloadIfNewResult>::fail(ErrorKind::InvalidPayload,
                                                      "Invisible Folder metadata did not contain __revisions.");

        DownloadIfNewResult result;
        result.revision = revision->second.value;
        result.metadata = *currentMetadata;
        if (knownRevision && *knownRevision == result.revision)
            return result;

        result.downloaded = true;
        if (destination)
        {
            const auto saved = downloadToFile(referenceId, *destination);
            if (!saved)
                return Result<DownloadIfNewResult>::fail(saved.error().kind, saved.error().message);
            result.destination = std::move(destination);
        }
        else
        {
            const auto bytes = download(referenceId);
            if (!bytes)
                return Result<DownloadIfNewResult>::fail(bytes.error().kind, bytes.error().message);
            result.bytes = *bytes;
        }
        return result;
    }

    void InvisibleFolder::setToken(std::string token)
    {
        std::lock_guard lock(mutex_);
        std::fill(token_.begin(), token_.end(), '\0');
        token_ = std::move(token);
    }

    void InvisibleFolder::clearToken() noexcept
    {
        std::lock_guard lock(mutex_);
        std::fill(token_.begin(), token_.end(), '\0');
        token_.clear();
    }
}
