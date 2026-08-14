#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace syslocker::bedrock
{
    struct Config
    {
        std::string systemId;
        std::string version = "bypass";
        std::string hwid = "1";
        std::chrono::seconds beatRate{30};
        std::chrono::milliseconds requestTimeout{15000};
        std::chrono::seconds maxServerClockSkew{120};
        std::string baseUrl = "https://systemlocker.net";
        std::string invisibleFolderBaseUrl = "https://invisiblefolder.net";
        std::string userAgent = "systemlocker-bedrock-cpp/0.2";
        std::optional<std::string> programDigest;
        std::optional<std::string> pinnedTlsPublicKeySha256Base64;
        std::optional<std::string> invisibleFolderPinnedTlsPublicKeySha256Base64;

        // Required only to read Invisible Folder metadata for API Available,
        // Password Protected, and System Locker Simple files. System Locker
        // Advanced files use the short-lived token returned by Bedrock instead.
        std::optional<std::string> invisibleFolderApiKey;

        // Base64url-encoded raw 32-byte Ed25519 public key downloaded through
        // the authenticated System Locker developer dashboard.
        std::string signingPublicKey;

        // Enabled by default. Tests and event-loop applications can disable
        // this and drive Client::heartbeatNow() themselves.
        bool automaticHeartbeats = true;
    };
}
