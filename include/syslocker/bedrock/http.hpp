#pragma once

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

    struct HttpResponse
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

    class IHttpClient
    {
    public:
        virtual ~IHttpClient() = default;
        virtual HttpResponse post(std::string_view url, const FormFields &fields) = 0;
    };

    struct CurlHttpOptions
    {
        std::chrono::milliseconds timeout{15000};
        std::string userAgent = "systemlocker-bedrock-cpp/0.1";
        std::string pinnedPublicKey;
    };

    std::unique_ptr<IHttpClient> makeCurlHttpClient(CurlHttpOptions options = {});
}
