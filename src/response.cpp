#include "syslocker/bedrock/response.hpp"
#include "syslocker/bedrock/http.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace syslocker::bedrock
{
    namespace
    {
        using Entry = std::pair<std::string_view, ResponseCode>;
        constexpr std::array<Entry, 29> kCodes{{
            {"OK", ResponseCode::Ok},
            {"OUTDATED", ResponseCode::Outdated},
            {"MISSING_FIELD", ResponseCode::MissingField},
            {"INVALID_REQUEST", ResponseCode::InvalidRequest},
            {"INVALID_SYSTEM", ResponseCode::InvalidSystem},
            {"INVALID_CREDENTIALS", ResponseCode::InvalidCredentials},
            {"GOOGLE_SSO_REQUIRED", ResponseCode::GoogleSsoRequired},
            {"USER_NOT_VERIFIED", ResponseCode::UserNotVerified},
            {"INVALID_KEY", ResponseCode::InvalidKey},
            {"KEY_FROZEN", ResponseCode::KeyFrozen},
            {"HWID_BANNED", ResponseCode::HwidBanned},
            {"HWID_MISMATCH", ResponseCode::HwidMismatch},
            {"SPOOF_SUSPECTED", ResponseCode::SpoofSuspected},
            {"SYSTEM_PAUSED", ResponseCode::SystemPaused},
            {"PLAN_INACTIVE", ResponseCode::PlanInactive},
            {"PRODUCTION_AUTH_UNAVAILABLE", ResponseCode::ProductionAuthUnavailable},
            {"USER_LIMIT_REACHED", ResponseCode::UserLimitReached},
            {"EXPIRED_KEY", ResponseCode::ExpiredKey},
            {"PROGRAM_DIGEST_MISMATCH", ResponseCode::ProgramDigestMismatch},
            {"INVALID_BEATRATE", ResponseCode::InvalidBeatRate},
            {"NO_ACTIVE_SIGNING_KEY", ResponseCode::NoActiveSigningKey},
            {"INVALID_SESSION", ResponseCode::InvalidSession},
            {"SESSION_TERMINATED", ResponseCode::SessionTerminated},
            {"STALE_SESSION", ResponseCode::StaleSession},
            {"HEARTBEAT_TOO_EARLY", ResponseCode::HeartbeatTooEarly},
            {"HEARTBEAT_VARIANCE_EXCEEDED", ResponseCode::HeartbeatVarianceExceeded},
            {"SIGNING_KEY_REVOKED", ResponseCode::SigningKeyRevoked},
            {"CONCURRENT_HEARTBEAT", ResponseCode::ConcurrentHeartbeat},
            {"INTERNAL_ERROR", ResponseCode::InternalError},
        }};
    }

    ResponseCode responseCodeFromString(std::string_view value) noexcept
    {
        const auto entry = std::find_if(kCodes.begin(), kCodes.end(), [value](const Entry &candidate)
                                        { return candidate.first == value; });
        return entry == kCodes.end() ? ResponseCode::Unknown : entry->second;
    }

    std::string_view toString(ResponseCode code) noexcept
    {
        const auto entry = std::find_if(kCodes.begin(), kCodes.end(), [code](const Entry &candidate)
                                        { return candidate.second == code; });
        return entry == kCodes.end() ? std::string_view{"UNKNOWN"} : entry->first;
    }

    std::string HttpResponse::header(std::string_view name) const
    {
        std::string normalized(name);
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char character)
                       { return static_cast<char>(std::tolower(character)); });
        const auto found = headers.find(normalized);
        if (found != headers.end())
            return found->second;

        for (const auto &[headerName, value] : headers)
        {
            if (headerName.size() != normalized.size())
                continue;
            const bool matches = std::equal(headerName.begin(), headerName.end(), normalized.begin(),
                                            [](unsigned char left, unsigned char right)
                                            {
                                                return std::tolower(left) == std::tolower(right);
                                            });
            if (matches)
                return value;
        }
        return {};
    }
}
