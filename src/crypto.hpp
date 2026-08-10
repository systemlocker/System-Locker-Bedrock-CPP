#pragma once

#include "syslocker/bedrock/config.hpp"
#include "syslocker/bedrock/http.hpp"
#include "syslocker/bedrock/response.hpp"
#include "syslocker/bedrock/result.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace syslocker::bedrock::detail
{
    Result<std::vector<unsigned char>> base64UrlDecode(std::string_view value);
    std::string base64UrlEncode(const unsigned char *bytes, std::size_t length);
    Result<std::string> generateChallenge();
    Result<std::string> sha256Hex(std::string_view value);

    Result<Response> verifySignedResponse(const Config &config,
                                          const HttpResponse &httpResponse,
                                          std::string_view expectedChallenge);

    Result<Response> parseUnsignedRevocation(const Config &config,
                                             const HttpResponse &httpResponse,
                                             std::string_view expectedChallenge);
}
