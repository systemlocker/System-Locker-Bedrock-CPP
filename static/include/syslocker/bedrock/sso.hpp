#pragma once

#include "export.hpp"

#include <string>
#include <string_view>

namespace syslocker::bedrock
{
    // Google-backed accounts have no local password on the server. When a
    // username/password initialization arrives without a valid SSO password,
    // the server answers a signed GOOGLE_SSO_REQUIRED denial carrying sso_url.
    // These helpers build and open that portal; after Google sign-in the page
    // shows a system-specific password (valid 180 days) that is then used as
    // the account password.

    /// Outcome of beginGoogleSso: the portal URL is always returned so flows
    /// without a browser can hand it to the developer; opened reports whether
    /// the launch succeeded.
    struct SsoLaunch
    {
        std::string url;
        bool opened = false;
    };

    /// Returns the Google SSO portal URL for a system, percent-encoding the
    /// system id exactly like the server's rawurlencode.
    SYSLOCKER_BEDROCK_API std::string googleSsoUrl(std::string_view systemId);

    /// Launches the default browser at a URL. Reports whether a browser
    /// launched; hosts without one (servers, containers) return false and the
    /// caller falls back to displaying the URL.
    SYSLOCKER_BEDROCK_API bool openUrl(const std::string &url) noexcept;

    /// Opens the Google SSO portal for a system in the default browser.
    SYSLOCKER_BEDROCK_API SsoLaunch beginGoogleSso(std::string_view systemId);
}
