#include "syslocker/bedrock/http.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <mutex>
#include <stdexcept>

namespace syslocker::bedrock
{
    namespace
    {
        std::once_flag curlInitialization;

        void initializeCurl()
        {
            if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
                throw std::runtime_error("libcurl global initialization failed.");
        }

        std::string trim(std::string value)
        {
            const auto notWhitespace = [](unsigned char character)
            {
                return !std::isspace(character);
            };
            value.erase(value.begin(), std::find_if(value.begin(), value.end(), notWhitespace));
            value.erase(std::find_if(value.rbegin(), value.rend(), notWhitespace).base(), value.end());
            return value;
        }

        std::size_t writeBody(char *data, std::size_t size, std::size_t count, void *context)
        {
            const std::size_t bytes = size * count;
            static_cast<std::string *>(context)->append(data, bytes);
            return bytes;
        }

        std::size_t writeHeader(char *data, std::size_t size, std::size_t count, void *context)
        {
            const std::size_t bytes = size * count;
            std::string line(data, bytes);
            const auto colon = line.find(':');
            if (colon == std::string::npos)
                return bytes;

            std::string name = trim(line.substr(0, colon));
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char character)
                           { return static_cast<char>(std::tolower(character)); });
            std::string value = trim(line.substr(colon + 1));
            static_cast<std::map<std::string, std::string> *>(context)->insert_or_assign(std::move(name), std::move(value));
            return bytes;
        }

        class CurlHttpClient final : public IHttpClient
        {
        public:
            explicit CurlHttpClient(CurlHttpOptions options) : options_(std::move(options))
            {
                std::call_once(curlInitialization, initializeCurl);
            }

            HttpResponse post(std::string_view url, const FormFields &fields) override
            {
                HttpResponse response;
                if (!url.starts_with("https://"))
                {
                    response.error = "Refusing a non-HTTPS Bedrock endpoint.";
                    return response;
                }

                CURL *curl = curl_easy_init();
                if (curl == nullptr)
                {
                    response.error = "libcurl request initialization failed.";
                    return response;
                }

                std::string encoded;
                for (const auto &[name, value] : fields)
                {
                    char *escapedName = curl_easy_escape(curl, name.c_str(), static_cast<int>(name.size()));
                    char *escapedValue = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.size()));
                    if (escapedName == nullptr || escapedValue == nullptr)
                    {
                        if (escapedName != nullptr)
                            curl_free(escapedName);
                        if (escapedValue != nullptr)
                            curl_free(escapedValue);
                        curl_easy_cleanup(curl);
                        response.error = "libcurl form encoding failed.";
                        return response;
                    }
                    if (!encoded.empty())
                        encoded.push_back('&');
                    encoded.append(escapedName).push_back('=');
                    encoded.append(escapedValue);
                    curl_free(escapedName);
                    curl_free(escapedValue);
                }

                const std::string urlString(url);
                curl_easy_setopt(curl, CURLOPT_URL, urlString.c_str());
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encoded.data());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(encoded.size()));
                curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(options_.timeout.count()));
                curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(options_.timeout.count()));
                curl_easy_setopt(curl, CURLOPT_USERAGENT, options_.userAgent.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
                curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
                curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#if LIBCURL_VERSION_NUM >= 0x075500
                curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
                curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#endif
                if (!options_.pinnedPublicKey.empty())
                    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, options_.pinnedPublicKey.c_str());

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeBody);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, writeHeader);
                curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);

                curl_slist *headers = nullptr;
                headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
                headers = curl_slist_append(headers, "Accept: text/plain, application/json");
                headers = curl_slist_append(headers, "Cache-Control: no-store");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                char errorBuffer[CURL_ERROR_SIZE]{};
                curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);

                const CURLcode result = curl_easy_perform(curl);
                if (result != CURLE_OK)
                    response.error = errorBuffer[0] != '\0' ? errorBuffer : curl_easy_strerror(result);
                else
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

                std::fill(encoded.begin(), encoded.end(), '\0');
                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);
                return response;
            }

            HttpResponse get(std::string_view url, const HttpHeaders &requestHeaders) override
            {
                HttpResponse response;
                if (!url.starts_with("https://"))
                {
                    response.error = "Refusing a non-HTTPS Invisible Folder endpoint.";
                    return response;
                }

                CURL *curl = curl_easy_init();
                if (curl == nullptr)
                {
                    response.error = "libcurl request initialization failed.";
                    return response;
                }

                const std::string urlString(url);
                curl_easy_setopt(curl, CURLOPT_URL, urlString.c_str());
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(options_.timeout.count()));
                curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(options_.timeout.count()));
                curl_easy_setopt(curl, CURLOPT_USERAGENT, options_.userAgent.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
                curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
                curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#if LIBCURL_VERSION_NUM >= 0x075500
                curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
#else
                curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#endif
                if (!options_.invisibleFolderPinnedPublicKey.empty())
                    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, options_.invisibleFolderPinnedPublicKey.c_str());

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeBody);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, writeHeader);
                curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);

                curl_slist *headers = nullptr;
                headers = curl_slist_append(headers, "Accept: application/json");
                headers = curl_slist_append(headers, "Cache-Control: no-store");
                for (const auto &[name, value] : requestHeaders)
                {
                    const std::string header = name + ": " + value;
                    headers = curl_slist_append(headers, header.c_str());
                }
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                char errorBuffer[CURL_ERROR_SIZE]{};
                curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
                const CURLcode result = curl_easy_perform(curl);
                if (result != CURLE_OK)
                    response.error = errorBuffer[0] != '\0' ? errorBuffer : curl_easy_strerror(result);
                else
                    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);
                return response;
            }

        private:
            CurlHttpOptions options_;
        };
    }

    std::unique_ptr<IHttpClient> makeCurlHttpClient(CurlHttpOptions options)
    {
        return std::make_unique<CurlHttpClient>(std::move(options));
    }
}
