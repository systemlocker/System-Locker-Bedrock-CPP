#include "syslocker/bedrock/client.hpp"
#include "syslocker/bedrock/invisible_folder.hpp"

#include "crypto.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <optional>
#include <string_view>
#include <thread>

namespace syslocker::bedrock
{
    namespace
    {
        constexpr std::string_view kInitPath = "/auth/bedrock/init";
        constexpr std::string_view kBeatPath = "/auth/bedrock/beat";
        constexpr auto kClockJumpTolerance = std::chrono::seconds(2);

        std::string endpoint(const std::string &baseUrl, std::string_view path)
        {
            if (!baseUrl.empty() && baseUrl.back() == '/')
                return baseUrl.substr(0, baseUrl.size() - 1) + std::string(path);
            return baseUrl + std::string(path);
        }

        void wipe(std::string &value) noexcept
        {
            volatile char *bytes = value.empty() ? nullptr : &value[0];
            for (std::size_t index = 0; index < value.size(); ++index)
                bytes[index] = '\0';
            value.clear();
        }

        void wipe(FormFields &fields) noexcept
        {
            for (auto &field : fields)
                wipe(field.second);
        }

        Error responseError(const Response &response)
        {
            return Error{ErrorKind::SessionTerminated,
                         response.terminationMessage.value_or(response.humanResponse)};
        }
    }

    class BedrockSession : public std::enable_shared_from_this<BedrockSession>
    {
    public:
        BedrockSession(IHttpClient &http,
                       Config config,
                       std::string token,
                       HeartbeatFailureHook hook)
            : http_(http), config_(std::move(config)), token_(std::move(token)), hook_(std::move(hook))
        {
        }

        ~BedrockSession()
        {
            stop();
            if (thread_.joinable())
            {
                if (thread_.get_id() == std::this_thread::get_id())
                    thread_.detach();
                else
                    thread_.join();
            }
            wipe(token_);
        }

        void start()
        {
            thread_ = std::thread([self = shared_from_this()]
                                  { self->run(); });
        }

        void stop() noexcept
        {
            stop_.store(true, std::memory_order_release);
            alive_.store(false, std::memory_order_release);
            condition_.notify_all();
        }

        void wait() noexcept
        {
            if (thread_.joinable() && thread_.get_id() != std::this_thread::get_id())
                thread_.join();
        }

        bool alive() const noexcept { return alive_.load(std::memory_order_acquire); }
        std::uint64_t count() const noexcept { return completed_.load(std::memory_order_relaxed); }

        void setHook(HeartbeatFailureHook hook)
        {
            std::lock_guard lock(hookMutex_);
            hook_ = std::move(hook);
        }

        Result<Response> heartbeat(HeartbeatOptions options)
        {
            std::lock_guard requestLock(requestMutex_);
            if (!alive())
                return Result<Response>::fail(ErrorKind::SessionTerminated, "Bedrock session is not active.");

            auto challenge = detail::generateChallenge();
            if (!challenge)
                return failAndReturn(challenge.error());

            std::string token;
            {
                std::lock_guard tokenLock(tokenMutex_);
                token = token_;
            }

            FormFields fields{
                {"session_token", token},
                {"system", config_.systemId},
                {"challenge", *challenge},
            };
            if (options.requestInvisibleFolderToken)
                fields.emplace_back("init-if", "true");

            HttpResponse httpResponse = http_.post(endpoint(config_.baseUrl, kBeatPath), fields);
            // A transport failure may mean the server committed the rotation
            // but the response was lost. Repeat the exact token/challenge once
            // so Bedrock can return its cached signed response.
            if (!httpResponse.error.empty())
                httpResponse = http_.post(endpoint(config_.baseUrl, kBeatPath), fields);
            wipe(fields);
            wipe(token);

            if (!httpResponse.ok())
            {
                const std::string message = !httpResponse.error.empty()
                                                ? "Bedrock heartbeat transport failed: " + httpResponse.error
                                                : "Bedrock heartbeat returned HTTP " + std::to_string(httpResponse.status) + ".";
                return failAndReturn(Error{ErrorKind::Transport, message});
            }

            Result<Response> response = detail::verifySignedResponse(config_, httpResponse, *challenge);
            if (!response && response.error().kind == ErrorKind::UnsignedResponse)
                response = detail::parseUnsignedRevocation(config_, httpResponse, *challenge);
            if (!response)
                return failAndReturn(response.error());

            if (response->code != ResponseCode::Ok || !response->authed || !response->sessionToken)
            {
                const Error error = responseError(*response);
                fail(error, *response);
                return *response;
            }
            if (!response->sessionToken->starts_with("BRF_"))
                return failAndReturn(Error{ErrorKind::InvalidPayload, "Bedrock heartbeat returned an invalid rotated token format."});

            {
                std::lock_guard tokenLock(tokenMutex_);
                wipe(token_);
                token_ = *response->sessionToken;
            }
            completed_.fetch_add(1, std::memory_order_relaxed);
            return *response;
        }

    private:
        Result<Response> failAndReturn(Error error)
        {
            fail(error, std::nullopt);
            return Result<Response>::fail(error.kind, std::move(error.message));
        }

        void fail(const Error &error, std::optional<Response> response)
        {
            const bool wasAlive = alive_.exchange(false, std::memory_order_acq_rel);
            stop_.store(true, std::memory_order_release);
            condition_.notify_all();
            if (!wasAlive)
                return;

            HeartbeatFailureHook hook;
            {
                std::lock_guard lock(hookMutex_);
                hook = hook_;
            }
            if (hook)
            {
                try
                {
                    hook(HeartbeatFailure{error, std::move(response), count()});
                }
                catch (...)
                {
                }
            }
        }

        void run() noexcept
        {
            auto previousSteady = std::chrono::steady_clock::now();
            auto previousSystem = std::chrono::system_clock::now();
            try
            {
                while (!stop_.load(std::memory_order_acquire))
                {
                    std::unique_lock waitLock(waitMutex_);
                    if (condition_.wait_for(waitLock, config_.beatRate, [this]
                                            { return stop_.load(std::memory_order_acquire); }))
                        return;
                    waitLock.unlock();

                    const auto currentSteady = std::chrono::steady_clock::now();
                    const auto currentSystem = std::chrono::system_clock::now();
                    const auto steadyElapsed = currentSteady - previousSteady;
                    const auto systemElapsed = currentSystem - previousSystem;
                    const auto skew = steadyElapsed > systemElapsed ? steadyElapsed - systemElapsed : systemElapsed - steadyElapsed;
                    if (skew > kClockJumpTolerance)
                    {
                        fail(Error{ErrorKind::LocalFailure, "Local clock changed unexpectedly during a Bedrock session."}, std::nullopt);
                        return;
                    }
                    previousSteady = currentSteady;
                    previousSystem = currentSystem;

                    const auto response = heartbeat({});
                    if (!response || !alive())
                        return;
                }
            }
            catch (const std::exception &error)
            {
                fail(Error{ErrorKind::LocalFailure, std::string("Bedrock heartbeat worker failed: ") + error.what()}, std::nullopt);
            }
            catch (...)
            {
                fail(Error{ErrorKind::LocalFailure, "Bedrock heartbeat worker failed unexpectedly."}, std::nullopt);
            }
        }

        IHttpClient &http_;
        Config config_;
        mutable std::mutex tokenMutex_;
        std::string token_;
        std::mutex requestMutex_;
        std::mutex hookMutex_;
        HeartbeatFailureHook hook_;
        std::atomic<bool> alive_{true};
        std::atomic<bool> stop_{false};
        std::atomic<std::uint64_t> completed_{0};
        std::mutex waitMutex_;
        std::condition_variable condition_;
        std::thread thread_;
    };

    Client::Client(Config config)
        : Client(std::move(config), nullptr)
    {
    }

    Client::Client(Config config, std::unique_ptr<IHttpClient> http)
        : config_(std::move(config)), http_(std::move(http))
    {
        if (!http_)
        {
            CurlHttpOptions options;
            options.timeout = config_.requestTimeout;
            options.userAgent = config_.userAgent;
            if (config_.pinnedTlsPublicKeySha256Base64)
                options.pinnedPublicKey = "sha256//" + *config_.pinnedTlsPublicKeySha256Base64;
            if (config_.invisibleFolderPinnedTlsPublicKeySha256Base64)
                options.invisibleFolderPinnedPublicKey = "sha256//" + *config_.invisibleFolderPinnedTlsPublicKeySha256Base64;
            http_ = makeCurlHttpClient(std::move(options));
        }
        invisibleFolder_ = std::make_unique<InvisibleFolder>(*http_, config_);
    }

    Client::~Client()
    {
        shutdown();
    }

    Result<void *> Client::validateConfig() const
    {
        if (config_.hwidMode != "legacy" && config_.hwidMode != "sl-hwid")
            return Result<void *>::fail(ErrorKind::Configuration, "HWID mode must be \"legacy\" or \"sl-hwid\".");
        // An explicit hwid (including "1", device checks disabled) always
        // wins; the SL-HWID module only runs for an empty hwid.
        if (config_.systemId.size() != 20 ||
            !std::all_of(config_.systemId.begin(), config_.systemId.end(), [](unsigned char character)
                         {
                             return (character >= 'A' && character <= 'Z') ||
                                    (character >= 'a' && character <= 'z') ||
                                    (character >= '0' && character <= '9');
                         }))
            return Result<void *>::fail(ErrorKind::Configuration, "System ID must be exactly 20 alphanumeric characters.");
        if (config_.beatRate < std::chrono::seconds(25) || config_.beatRate > std::chrono::seconds(3600))
            return Result<void *>::fail(ErrorKind::Configuration, "Bedrock heartbeat interval must be from 25 through 3600 seconds.");
        if (!config_.baseUrl.starts_with("https://"))
            return Result<void *>::fail(ErrorKind::Configuration, "Bedrock base URL must use HTTPS.");
        if (config_.maxServerClockSkew <= std::chrono::seconds::zero() ||
            config_.maxServerClockSkew > std::chrono::hours(1))
            return Result<void *>::fail(ErrorKind::Configuration, "Bedrock clock-skew allowance must be greater than zero and no more than one hour.");
        const auto decodedKey = detail::base64UrlDecode(config_.signingPublicKey);
        if (!decodedKey || decodedKey->size() != 32)
            return Result<void *>::fail(ErrorKind::Configuration, "The Bedrock public key must decode to exactly 32 bytes.");
        return static_cast<void *>(nullptr);
    }

    Result<std::shared_ptr<slhwid::Session>> Client::prepareSecretSharing(const std::string &identity)
    {
        {
            std::lock_guard lock(mutex_);
            const auto cached = ssSessions_.find(identity);
            if (cached != ssSessions_.end())
                return cached->second;
        }
        slhwid::Options options;
        if (config_.slHwidStore)
            options.storePath = *config_.slHwidStore;
        options.extraMandatory = config_.slHwidExtraMandatory;
        auto prepared = slhwid::prepare(options);
        if (!prepared)
            return Result<std::shared_ptr<slhwid::Session>>::fail(prepared.error().kind, prepared.error().message);
        auto session = std::make_shared<slhwid::Session>(std::move(*prepared));
        {
            std::lock_guard lock(mutex_);
            ssSessions_[identity] = session;
        }
        return session;
    }

    Result<AuthenticationResult> Client::authenticateWithKey(std::string licenseKey,
                                                               InitializationOptions options)
    {
        FormFields fields{{"key", licenseKey}};
        auto result = authenticate(std::move(fields), licenseKey, true, options);
        wipe(licenseKey);
        return result;
    }

    Result<AuthenticationResult> Client::authenticateWithPassword(std::string username,
                                                                    std::string password,
                                                                    InitializationOptions options)
    {
        FormFields fields{{"username", username}, {"password", password}};
        auto result = authenticate(std::move(fields), username, false, options);
        wipe(username);
        wipe(password);
        return result;
    }

    Result<AuthenticationResult> Client::authenticate(FormFields fields,
                                                       std::string_view identity,
                                                       bool keyAuthentication,
                                                       const InitializationOptions &options)
    {
        const auto validation = validateConfig();
        if (!validation)
        {
            wipe(fields);
            return Result<AuthenticationResult>::fail(validation.error().kind, validation.error().message);
        }

        shutdown();
        std::string hwidValue = config_.hwid;
        std::shared_ptr<slhwid::Session> ssSession;
        if (hwidValue.empty()) // SL-HWID mode: recover or enroll at auth time
        {
            auto prepared = prepareSecretSharing(std::string(identity));
            if (!prepared)
            {
                wipe(fields);
                return Result<AuthenticationResult>::fail(prepared.error().kind, prepared.error().message);
            }
            ssSession = *prepared;
            hwidValue = ssSession->hwid();
        }
        auto challenge = detail::generateChallenge();
        if (!challenge)
        {
            wipe(fields);
            return Result<AuthenticationResult>::fail(challenge.error().kind, challenge.error().message);
        }

        fields.emplace_back("system", config_.systemId);
        fields.emplace_back("hwid", hwidValue);
        fields.emplace_back("version", config_.version);
        fields.emplace_back("beatrate", std::to_string(config_.beatRate.count()));
        fields.emplace_back("challenge", *challenge);
        if (config_.programDigest)
            fields.emplace_back("digest", *config_.programDigest);
        if (options.requestInvisibleFolderToken)
            fields.emplace_back("init-if", "true");
        for (const auto &variable : options.variables)
            fields.emplace_back("variables[]", variable);

        const HttpResponse httpResponse = http_->post(endpoint(config_.baseUrl, kInitPath), fields);
        wipe(fields);
        if (!httpResponse.ok())
        {
            const std::string message = !httpResponse.error.empty()
                                            ? "Bedrock initialization transport failed: " + httpResponse.error
                                            : "Bedrock initialization returned HTTP " + std::to_string(httpResponse.status) + ".";
            return Result<AuthenticationResult>::fail(ErrorKind::Transport, message);
        }

        auto response = detail::verifySignedResponse(config_, httpResponse, *challenge);
        if (!response)
            return Result<AuthenticationResult>::fail(response.error().kind, response.error().message);

        const bool authenticatedCode = response->code == ResponseCode::Ok || response->code == ResponseCode::Outdated;
        if (response->authed != authenticatedCode)
            return Result<AuthenticationResult>::fail(ErrorKind::InvalidPayload, "Bedrock authentication flags contradict the response code.");

        AuthenticationResult result{*response, false};
        if (!response->authed && (!response->variables.empty() || response->invisibleFolderToken))
            return Result<AuthenticationResult>::fail(ErrorKind::InvalidPayload,
                                                       "A rejected Bedrock initialization returned successful-only data.");
        if (!response->authed)
            return result;
        if (!response->sessionToken)
            return Result<AuthenticationResult>::fail(ErrorKind::InvalidPayload, "Authenticated Bedrock response did not contain a session token.");
        if (!response->sessionToken->starts_with("BRK_"))
            return Result<AuthenticationResult>::fail(ErrorKind::InvalidPayload, "Bedrock initialization returned an invalid session token format.");

        auto identityHash = detail::sha256Hex(identity);
        if (!identityHash)
            return Result<AuthenticationResult>::fail(identityHash.error().kind, identityHash.error().message);
        const auto &responseHash = keyAuthentication ? response->licenseKeyHash : response->usernameHash;
        if (!responseHash || *responseHash != *identityHash)
            return Result<AuthenticationResult>::fail(ErrorKind::InvalidPayload, "Bedrock response identity hash does not match the authentication request.");

        // The server accepted this identity on this device: re-center the
        // secret-sharing shares on the hardware observed this launch.
        // Failures are non-fatal — the next launch re-derives.
        if (ssSession)
            ssSession->commit();

        auto session = std::make_shared<BedrockSession>(*http_, config_, *response->sessionToken, failureHook_);
        if (config_.automaticHeartbeats)
            session->start();
        {
            std::lock_guard lock(mutex_);
            session_ = std::move(session);
        }
        if (response->invisibleFolderToken)
            invisibleFolder_->setToken(*response->invisibleFolderToken);
        result.sessionStarted = true;
        return result;
    }

    Result<Response> Client::heartbeatNow(HeartbeatOptions options)
    {
        std::shared_ptr<BedrockSession> session;
        {
            std::lock_guard lock(mutex_);
            session = session_;
        }
        if (!session)
            return Result<Response>::fail(ErrorKind::SessionTerminated, "No Bedrock session is active.");
        auto response = session->heartbeat(options);
        if (response && response->authed && response->invisibleFolderToken)
            invisibleFolder_->setToken(*response->invisibleFolderToken);
        return response;
    }

    InvisibleFolder &Client::invisibleFolder() noexcept
    {
        return *invisibleFolder_;
    }

    const InvisibleFolder &Client::invisibleFolder() const noexcept
    {
        return *invisibleFolder_;
    }

    void Client::onHeartbeatFailure(HeartbeatFailureHook hook)
    {
        std::lock_guard lock(mutex_);
        failureHook_ = std::move(hook);
        if (session_)
            session_->setHook(failureHook_);
    }

    bool Client::isAuthenticated() const noexcept
    {
        std::lock_guard lock(mutex_);
        return session_ && session_->alive();
    }

    std::uint64_t Client::heartbeatCount() const noexcept
    {
        std::lock_guard lock(mutex_);
        return session_ ? session_->count() : 0;
    }

    void Client::shutdown() noexcept
    {
        std::shared_ptr<BedrockSession> previous;
        {
            std::lock_guard lock(mutex_);
            previous = std::move(session_);
        }
        if (previous)
        {
            previous->stop();
            previous->wait();
        }
        if (invisibleFolder_)
            invisibleFolder_->clearToken();
    }
}
