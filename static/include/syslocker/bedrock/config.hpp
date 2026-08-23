#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace syslocker::bedrock
{
    struct Config
    {
        std::string systemId;
        std::string version = "bypass";
        std::string hwid = "1";

        // How the device identifier is derived when hwid is empty. "sl-hwid"
        // runs the fault-tolerant module at authentication time; "legacy"
        // leaves the field for the application's own identifier. An explicit
        // hwid (including "1", device checks disabled) always wins.
        std::string hwidMode = "sl-hwid";

        // Optionally redirects the secret-sharing module's storage to a
        // directory (files on every platform); empty uses the platform
        // default (the registry on Windows, an application-support
        // directory elsewhere).
        std::optional<std::string> slHwidStore;

        // Names additional hard-locked secret-sharing slots beyond the
        // module's own persisted value (for example, "machine_guid").
        std::vector<std::string> slHwidExtraMandatory;

        std::chrono::seconds beatRate{30};
        std::chrono::milliseconds requestTimeout{15000};
        std::chrono::seconds maxServerClockSkew{120};
        std::string baseUrl = "https://systemlocker.net";
        std::string invisibleFolderBaseUrl = "https://invisiblefolder.net";
        std::string userAgent = "systemlocker-bedrock-cpp/1.0";
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
