#pragma once

#include "export.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace syslocker::bedrock
{
    enum class ResponseCode
    {
        Ok,
        Outdated,
        MissingField,
        InvalidRequest,
        InvalidSystem,
        InvalidCredentials,
        UserNotVerified,
        InvalidKey,
        KeyFrozen,
        HwidBanned,
        HwidMismatch,
        SpoofSuspected,
        SystemPaused,
        PlanInactive,
        ProductionAuthUnavailable,
        UserLimitReached,
        ExpiredKey,
        ProgramDigestMismatch,
        InvalidBeatRate,
        NoActiveSigningKey,
        InvalidSession,
        SessionTerminated,
        StaleSession,
        HeartbeatTooEarly,
        HeartbeatVarianceExceeded,
        SigningKeyRevoked,
        ConcurrentHeartbeat,
        InternalError,
        Unknown,
    };

    SYSLOCKER_BEDROCK_API ResponseCode responseCodeFromString(std::string_view value) noexcept;
    SYSLOCKER_BEDROCK_API std::string_view toString(ResponseCode code) noexcept;

    struct Response
    {
        ResponseCode code = ResponseCode::Unknown;
        std::string responseCode;
        std::string humanResponse;
        bool isError = false;
        bool isFailure = false;
        bool authed = false;
        std::string protocolVersion;
        std::string system;
        std::string challenge;
        std::int64_t serverTime = 0;
        std::string humanTime;
        std::optional<std::string> sessionToken;
        std::optional<std::string> licenseKeyHash;
        std::optional<std::string> usernameHash;
        std::optional<std::string> terminationMessage;
        std::optional<std::string> invisibleFolderToken;

        // A missing server-side variable is represented by std::nullopt. This
        // is the C++ equivalent of Bedrock's JSON false default.
        std::map<std::string, std::optional<std::string>, std::less<>> variables;
    };
}
