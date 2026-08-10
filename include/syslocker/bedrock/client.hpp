#pragma once

#include "config.hpp"
#include "http.hpp"
#include "response.hpp"
#include "result.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

namespace syslocker::bedrock
{
    struct AuthenticationResult
    {
        Response response;
        bool sessionStarted = false;
    };

    struct HeartbeatFailure
    {
        Error error;
        std::optional<Response> response;
        std::uint64_t completedHeartbeats = 0;
    };

    using HeartbeatFailureHook = std::function<void(const HeartbeatFailure &)>;

    class BedrockSession;

    class Client
    {
    public:
        explicit Client(Config config);
        Client(Config config, std::unique_ptr<IHttpClient> http);
        ~Client();

        Client(const Client &) = delete;
        Client &operator=(const Client &) = delete;

        Result<AuthenticationResult> authenticateWithKey(std::string licenseKey);
        Result<AuthenticationResult> authenticateWithPassword(std::string username,
                                                               std::string password);

        Result<Response> heartbeatNow();
        void onHeartbeatFailure(HeartbeatFailureHook hook);
        bool isAuthenticated() const noexcept;
        std::uint64_t heartbeatCount() const noexcept;
        void shutdown() noexcept;

        const Config &config() const noexcept { return config_; }

    private:
        Result<AuthenticationResult> authenticate(FormFields fields,
                                                  std::string_view identity,
                                                  bool keyAuthentication);
        Result<void *> validateConfig() const;

        Config config_;
        std::unique_ptr<IHttpClient> http_;
        mutable std::mutex mutex_;
        std::shared_ptr<BedrockSession> session_;
        HeartbeatFailureHook failureHook_;
    };
}
