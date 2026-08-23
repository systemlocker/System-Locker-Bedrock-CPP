#pragma once

#include "config.hpp"
#include "http.hpp"
#include "invisible_folder.hpp"
#include "response.hpp"
#include "result.hpp"
#include "slhwid.hpp"
#include "sso.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace syslocker::bedrock
{
    struct AuthenticationResult
    {
        Response response;
        bool sessionStarted = false;
    };

    struct InitializationOptions
    {
        bool requestInvisibleFolderToken = false;
        std::vector<std::string> variables;
    };

    struct HeartbeatOptions
    {
        bool requestInvisibleFolderToken = false;
    };

    struct HeartbeatFailure
    {
        Error error;
        std::optional<Response> response;
        std::uint64_t completedHeartbeats = 0;
    };

    using HeartbeatFailureHook = std::function<void(const HeartbeatFailure &)>;

    class BedrockSession;

    class SYSLOCKER_BEDROCK_API Client
    {
    public:
        explicit Client(Config config);
        Client(Config config, std::unique_ptr<IHttpClient> http);
        ~Client();

        Client(const Client &) = delete;
        Client &operator=(const Client &) = delete;

        Result<AuthenticationResult> authenticateWithKey(std::string licenseKey,
                                                         InitializationOptions options = {});
        Result<AuthenticationResult> authenticateWithPassword(std::string username,
                                                               std::string password,
                                                               InitializationOptions options = {});

        Result<Response> heartbeatNow(HeartbeatOptions options = {});
        InvisibleFolder &invisibleFolder() noexcept;
        const InvisibleFolder &invisibleFolder() const noexcept;

        /// Returns the Google SSO portal URL for the configured system.
        std::string googleSsoUrl() const;
        /// Opens the Google SSO portal for the configured system; see
        /// sso.hpp for the SsoLaunch contract.
        SsoLaunch beginGoogleSso() const;
        void onHeartbeatFailure(HeartbeatFailureHook hook);
        bool isAuthenticated() const noexcept;
        std::uint64_t heartbeatCount() const noexcept;
        void shutdown() noexcept;

        const Config &config() const noexcept { return config_; }

    private:
        Result<AuthenticationResult> authenticate(FormFields fields,
                                                  std::string_view identity,
                                                  bool keyAuthentication,
                                                  const InitializationOptions &options);
        Result<void *> validateConfig() const;
        Result<std::shared_ptr<slhwid::Session>> prepareSecretSharing(const std::string &identity);

        Config config_;
        std::unique_ptr<IHttpClient> http_;
        mutable std::mutex mutex_;
        std::shared_ptr<BedrockSession> session_;
        std::unique_ptr<InvisibleFolder> invisibleFolder_;
        HeartbeatFailureHook failureHook_;
        std::map<std::string, std::shared_ptr<slhwid::Session>> ssSessions_;
    };
}
