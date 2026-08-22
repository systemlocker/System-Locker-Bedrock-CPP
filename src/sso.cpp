#include "syslocker/bedrock/sso.hpp"
#include "syslocker/bedrock/client.hpp"

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#if defined(_MSC_VER)
#pragma comment(lib, "shell32.lib")
#endif
#else
#include <cstdlib>
#endif

namespace syslocker::bedrock
{
    namespace
    {
        constexpr std::string_view kGoogleSsoPortal = "https://systemlocker.net/user/sso?system=";
    }

    std::string googleSsoUrl(std::string_view systemId)
    {
        static constexpr char kHexDigits[] = "0123456789ABCDEF";

        std::string url(kGoogleSsoPortal);
        url.reserve(url.size() + systemId.size());
        for (const unsigned char character : systemId)
        {
            const bool unreserved = (character >= 'A' && character <= 'Z') ||
                                    (character >= 'a' && character <= 'z') ||
                                    (character >= '0' && character <= '9') ||
                                    character == '-' || character == '_' ||
                                    character == '.' || character == '~';
            if (unreserved)
            {
                url.push_back(static_cast<char>(character));
            }
            else
            {
                url.push_back('%');
                url.push_back(kHexDigits[character >> 4]);
                url.push_back(kHexDigits[character & 0x0F]);
            }
        }
        return url;
    }

    bool openUrl(const std::string &url) noexcept
    {
        if (url.empty())
            return false;
#if defined(_WIN32)
        const int wideSize = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
        if (wideSize <= 0)
            return false;
        std::wstring wideUrl(static_cast<std::size_t>(wideSize), L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, wideUrl.data(), wideSize) != wideSize)
            return false;

        const HINSTANCE result = ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return reinterpret_cast<INT_PTR>(result) > 32;
#elif defined(__APPLE__)
        // The portal URL is percent-encoded, so it cannot introduce shell
        // metacharacters. The opener hands off to the browser and exits.
        return std::system(("open \"" + url + "\"").c_str()) == 0;
#else
        return std::system(("xdg-open \"" + url + "\" >/dev/null 2>&1").c_str()) == 0;
#endif
    }

    SsoLaunch beginGoogleSso(std::string_view systemId)
    {
        SsoLaunch launch;
        launch.url = googleSsoUrl(systemId);
        launch.opened = openUrl(launch.url);
        return launch;
    }

    std::string Client::googleSsoUrl() const
    {
        return bedrock::googleSsoUrl(config_.systemId);
    }

    SsoLaunch Client::beginGoogleSso() const
    {
        return bedrock::beginGoogleSso(config_.systemId);
    }
}
