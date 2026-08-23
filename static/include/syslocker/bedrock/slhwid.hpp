#pragma once

#include "syslocker/bedrock/result.hpp"

#include <memory>
#include <string>
#include <vector>

namespace syslocker::bedrock::slhwid
{
    /// Configuration for one prepare call.
    struct Options
    {
        /// Optionally redirects storage to a directory (files on every
        /// platform). Empty uses the platform default: the registry on
        /// Windows, a per-user application-support directory elsewhere.
        std::string storePath;

        /// Names additional hard-locked slots beyond the default "slstore".
        std::vector<std::string> extraMandatory;

        /// Discards any stored helper data and enrolls a fresh key (new
        /// HWID); the application must then run its server-side device reset.
        bool forceReenroll = false;
    };

    /// One prepared secret-sharing HWID. hwid() is available immediately;
    /// commit() persists a re-centered share set and must only be called
    /// after the server accepted the authentication that used the hwid.
    class Session
    {
    public:
        Session(std::string hwid,
                bool freshlyEnrolled,
                std::vector<std::string> driftedSlots,
                bool pendingRefresh,
                std::shared_ptr<void> state);
        ~Session();

        Session(Session &&) = default;
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;

        /// The transmitted device identifier (43 characters, base64url).
        const std::string &hwid() const noexcept;

        /// Whether this session created a key the server has never seen.
        bool freshlyEnrolled() const noexcept;

        /// Enrolled slots that were dead at prepare time.
        const std::vector<std::string> &driftedSlots() const noexcept;

        /// Whether any slot was dead (commit will re-center).
        bool pendingRefresh() const noexcept;

        /// Re-shares the recovered key over the hardware observed at prepare
        /// time and persists the new helper data. Failures are non-fatal:
        /// the next launch re-derives everything.
        void commit() noexcept;

    private:
        std::string hwid_;
        bool freshlyEnrolled_;
        std::vector<std::string> driftedSlots_;
        bool pendingRefresh_;
        std::shared_ptr<void> state_; // internal key/store wiring; wiped on commit
    };

    /// Collects factors and recovers (or enrolls) the secret-sharing HWID for
    /// the current device. Enrollment persists immediately; a recovered
    /// session persists nothing until Session::commit.
    Result<Session> prepare(const Options &options);
}
