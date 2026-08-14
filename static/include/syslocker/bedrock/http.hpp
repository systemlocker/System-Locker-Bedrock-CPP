#pragma once

#include "export.hpp"

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace syslocker::bedrock
{
    using FormFields = std::vector<std::pair<std::string, std::string>>;
    using HttpHeaders = std::vector<std::pair<std::string, std::string>>;

    struct SYSLOCKER_BEDROCK_API HttpResponse
    {
        long status = 0;
        std::string body;
        std::string error;
        std::map<std::string, std::string> headers;

        bool ok() const noexcept
        {
            return error.empty() && status >= 200 && status < 300;
        }

        std::string header(std::string_view name) const;
    };

    class SYSLOCKER_BEDROCK_API IHttpClient
    {
    public:
        virtual ~IHttpClient() = default;
        virtual HttpResponse post(std::string_view url, const FormFields &fields) = 0;

        // Metadata requests require headers and use GET. The default keeps
        // existing custom transports source-compatible until they opt in.
        virtual HttpResponse get(std::string_view, const HttpHeaders &)
        {
            HttpResponse response;
            response.error = "This HTTP client does not support GET requests.";
            return response;
        }
    };

    struct CurlHttpOptions
    {
        std::chrono::milliseconds timeout{15000};
        std::string userAgent = "systemlocker-bedrock-cpp/0.2";
        std::string pinnedPublicKey;
        std::string invisibleFolderPinnedPublicKey;
    };

    SYSLOCKER_BEDROCK_API std::unique_ptr<IHttpClient> makeCurlHttpClient(CurlHttpOptions options = {});
}
