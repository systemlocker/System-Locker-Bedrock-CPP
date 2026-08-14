#pragma once

#include "syslocker/bedrock/http.hpp"

#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace syslocker::bedrock::test
{
    class FakeHttp final : public IHttpClient
    {
    public:
        struct Request
        {
            std::string url;
            FormFields fields;
            HttpHeaders headers;
            std::string method = "POST";
        };

        using Handler = std::function<HttpResponse(const Request &)>;

        explicit FakeHttp(Handler handler) : handler_(std::move(handler)) {}

        HttpResponse post(std::string_view url, const FormFields &fields) override
        {
            Request request{std::string(url), fields};
            {
                std::lock_guard lock(mutex_);
                requests_.push_back(request);
            }
            return handler_(request);
        }

        HttpResponse get(std::string_view url, const HttpHeaders &headers) override
        {
            Request request{std::string(url), {}, headers, "GET"};
            {
                std::lock_guard lock(mutex_);
                requests_.push_back(request);
            }
            return handler_(request);
        }

        std::vector<Request> requests() const
        {
            std::lock_guard lock(mutex_);
            return requests_;
        }

        static std::string field(const Request &request, std::string_view name)
        {
            for (const auto &[fieldName, value] : request.fields)
            {
                if (fieldName == name)
                    return value;
            }
            return {};
        }

        static std::string header(const Request &request, std::string_view name)
        {
            for (const auto &[headerName, value] : request.headers)
            {
                if (headerName == name)
                    return value;
            }
            return {};
        }

    private:
        Handler handler_;
        mutable std::mutex mutex_;
        std::vector<Request> requests_;
    };
}
