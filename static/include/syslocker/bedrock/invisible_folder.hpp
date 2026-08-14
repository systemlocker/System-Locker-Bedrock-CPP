#pragma once

#include "config.hpp"
#include "export.hpp"
#include "result.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace syslocker::bedrock
{
    class IHttpClient;

    struct InvisibleFolderFile
    {
        std::string id;
        std::string referenceId;
        std::string name;
        std::string mimeType;
        std::uint64_t size = 0;
        std::uint64_t downloads = 0;
        std::string uploadedAt;
        std::int64_t permissionTypeId = 0;
    };

    struct InvisibleFolderMetadataValue
    {
        std::string value;
        std::optional<std::string> createdAt;
    };

    struct InvisibleFolderMetadata
    {
        InvisibleFolderFile file;
        std::map<std::string, InvisibleFolderMetadataValue, std::less<>> values;
    };

    struct DownloadIfNewResult
    {
        bool downloaded = false;
        std::string revision;
        InvisibleFolderMetadata metadata;
        std::optional<std::vector<std::uint8_t>> bytes;
        std::optional<std::filesystem::path> destination;
    };

    /// Accesses Invisible Folder through the authenticated Bedrock session.
    /// Advanced files use Bedrock's short-lived token. API Available, Password
    /// Protected, and System Locker Simple metadata use Config's API key.
    class SYSLOCKER_BEDROCK_API InvisibleFolder
    {
    public:
        InvisibleFolder(IHttpClient &http, const Config &config);

        bool hasToken() const noexcept;
        Result<std::vector<std::uint8_t>> download(std::string_view referenceId) const;
        Result<void *> downloadToFile(std::string_view referenceId,
                                     const std::filesystem::path &destination) const;
        Result<InvisibleFolderMetadata> metadata(
            std::string_view referenceId,
            const std::vector<std::string> &keys = {}) const;
        Result<DownloadIfNewResult> downloadIfNew(
            std::string_view referenceId,
            std::optional<std::string_view> knownRevision = std::nullopt,
            std::optional<std::filesystem::path> destination = std::nullopt) const;

    private:
        friend class Client;
        void setToken(std::string token);
        void clearToken() noexcept;

        IHttpClient &http_;
        const Config &config_;
        mutable std::mutex mutex_;
        std::string token_;
    };
}
