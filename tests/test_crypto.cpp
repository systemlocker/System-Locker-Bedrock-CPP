#include "test_framework.hpp"

#include "crypto.hpp"

#include <string>

using namespace syslocker::bedrock;

SLB_TEST("base64url: round trip preserves arbitrary bytes")
{
    const std::string input{"\0\x01\x7f\x80\xff", 5};
    const std::string encoded = detail::base64UrlEncode(
        reinterpret_cast<const unsigned char *>(input.data()), input.size());
    const auto decoded = detail::base64UrlDecode(encoded);
    SLB_REQUIRE(decoded);
    SLB_REQUIRE_EQ(std::string(reinterpret_cast<const char *>(decoded->data()), decoded->size()), input);
}

SLB_TEST("base64url: rejects padding and non-alphabet bytes")
{
    SLB_REQUIRE(!detail::base64UrlDecode("abcd="));
    SLB_REQUIRE(!detail::base64UrlDecode("abc+"));
    SLB_REQUIRE(!detail::base64UrlDecode("a"));
}

SLB_TEST("challenge: uses the documented 64 through 100 character range")
{
    const auto challenge = detail::generateChallenge();
    SLB_REQUIRE(challenge);
    SLB_REQUIRE(challenge->size() >= 64);
    SLB_REQUIRE(challenge->size() <= 100);
    SLB_REQUIRE(detail::base64UrlDecode(*challenge));
}

SLB_TEST("sha256: matches a standard lowercase vector")
{
    const auto hash = detail::sha256Hex("abc");
    SLB_REQUIRE(hash);
    SLB_REQUIRE_EQ(*hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
