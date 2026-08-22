#include "test_framework.hpp"

#include "fake_http.hpp"
#include "signing_fixture.hpp"
#include "syslocker/bedrock.hpp"

#include <atomic>
#include <memory>

using namespace syslocker::bedrock;
using namespace syslocker::bedrock::test;

SLB_TEST("authentication: verifies signature challenge system and identity hash")
{
    SigningFixture signer;
    auto config = configFor(signer);
    const auto expectedHash = detail::sha256Hex("LICENSE-KEY");
    SLB_REQUIRE(expectedHash);

    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               SLB_REQUIRE(request.url.ends_with("/auth/bedrock/init"));
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "system"), config.systemId);
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "hwid"), config.hwid);
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "beatrate"), "30");
                                               return signer.signedResponse(
                                                   config.systemId,
                                                   FakeHttp::field(request, "challenge"),
                                                   "OK",
                                                   true,
                                                   "BRK_initial",
                                                   "license_key_hash",
                                                   *expectedHash);
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(auth);
    SLB_REQUIRE(auth->sessionStarted);
    SLB_REQUIRE(auth->response.authed);
    SLB_REQUIRE_EQ(auth->response.code, ResponseCode::Ok);
    SLB_REQUIRE(client.isAuthenticated());
}

SLB_TEST("authentication: returns authenticated OUTDATED as a developer-visible session")
{
    SigningFixture signer;
    auto config = configFor(signer);
    const auto expectedHash = detail::sha256Hex("alice");
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return signer.signedResponse(
                                                   config.systemId,
                                                   FakeHttp::field(request, "challenge"),
                                                   "OUTDATED",
                                                   true,
                                                   "BRK_outdated",
                                                   "username_hash",
                                                   *expectedHash);
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithPassword("alice", "secret");
    SLB_REQUIRE(auth);
    SLB_REQUIRE(auth->sessionStarted);
    SLB_REQUIRE_EQ(auth->response.code, ResponseCode::Outdated);
}

SLB_TEST("authentication: signed user rejection remains inspectable and starts no session")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return signer.signedResponse(config.systemId,
                                                                            FakeHttp::field(request, "challenge"),
                                                                            "INVALID_KEY",
                                                                            false,
                                                                            {});
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("wrong");
    SLB_REQUIRE(auth);
    SLB_REQUIRE(!auth->sessionStarted);
    SLB_REQUIRE_EQ(auth->response.code, ResponseCode::InvalidKey);
    SLB_REQUIRE(!client.isAuthenticated());
}

SLB_TEST("google sso: signed GOOGLE_SSO_REQUIRED denial surfaces the portal url")
{
    SigningFixture signer;
    auto config = configFor(signer);
    const std::string portal = googleSsoUrl(config.systemId);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return signer.signedResponse(config.systemId,
                                                                            FakeHttp::field(request, "challenge"),
                                                                            "GOOGLE_SSO_REQUIRED",
                                                                            false,
                                                                            {},
                                                                            {},
                                                                            {},
                                                                            {},
                                                                            0,
                                                                            std::nullopt,
                                                                            {},
                                                                            portal);
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithPassword("alice", "not-the-sso-password");
    SLB_REQUIRE(auth);
    SLB_REQUIRE(!auth->sessionStarted);
    SLB_REQUIRE_EQ(auth->response.code, ResponseCode::GoogleSsoRequired);
    SLB_REQUIRE_EQ(auth->response.ssoUrl.value_or(""), portal);
    SLB_REQUIRE_EQ(client.googleSsoUrl(), portal);
}

SLB_TEST("google sso: portal url encodes the system id like rawurlencode")
{
    SLB_REQUIRE_EQ(googleSsoUrl("sys tem+1"), std::string("https://systemlocker.net/user/sso?system=sys%20tem%2B1"));
    SLB_REQUIRE_EQ(responseCodeFromString("GOOGLE_SSO_REQUIRED"), ResponseCode::GoogleSsoRequired);
    SLB_REQUIRE(toString(ResponseCode::GoogleSsoRequired) == "GOOGLE_SSO_REQUIRED");
    SLB_REQUIRE(!openUrl("")); // a malformed URL must fail closed, not crash
}

SLB_TEST("authentication: rejects a tampered signed body before JSON is trusted")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               auto response = signer.signedResponse(config.systemId,
                                                                                     FakeHttp::field(request, "challenge"),
                                                                                     "OK",
                                                                                     true,
                                                                                     "BRK_initial",
                                                                                     "license_key_hash",
                                                                                     *detail::sha256Hex("LICENSE-KEY"));
                                               response.body.back() = response.body.back() == 'A' ? 'B' : 'A';
                                               return response;
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::InvalidSignature);
}

SLB_TEST("authentication: rejects a valid signature that echoes the wrong challenge")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &)
                                           {
                                               return signer.signedResponse(config.systemId,
                                                                            std::string(64, 'x'),
                                                                            "OK",
                                                                            true,
                                                                            "BRK_initial",
                                                                            "license_key_hash",
                                                                            *detail::sha256Hex("LICENSE-KEY"));
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::InvalidPayload);
}

SLB_TEST("authentication: rejects unsigned diagnostic JSON")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return signer.unsignedRevocation(config.systemId,
                                                                                FakeHttp::field(request, "challenge"));
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::UnsignedResponse);
}

SLB_TEST("authentication: rejects a response signed by a different key")
{
    SigningFixture trustedSigner;
    SigningFixture otherSigner;
    auto config = configFor(trustedSigner);

    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return otherSigner.signedResponse(config.systemId,
                                                                                 FakeHttp::field(request, "challenge"),
                                                                                 "INVALID_KEY",
                                                                                 false,
                                                                                 {});
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::InvalidSignature);
}

SLB_TEST("authentication: rejects a correctly signed stale response")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return signer.signedResponse(config.systemId,
                                                                            FakeHttp::field(request, "challenge"),
                                                                            "INVALID_KEY",
                                                                            false,
                                                                            {},
                                                                            {},
                                                                            {},
                                                                            {},
                                                                            -600);
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::FreshnessViolation);
}

SLB_TEST("heartbeat: rotates tokens after a verified response")
{
    SigningFixture signer;
    auto config = configFor(signer);
    int heartbeat = 0;
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               const auto challenge = FakeHttp::field(request, "challenge");
                                               if (request.url.ends_with("/init"))
                                                   return signer.signedResponse(config.systemId,
                                                                                challenge,
                                                                                "OK",
                                                                                true,
                                                                                "BRK_initial",
                                                                                "license_key_hash",
                                                                                *detail::sha256Hex("LICENSE-KEY"));
                                               ++heartbeat;
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "session_token"),
                                                              heartbeat == 1 ? "BRK_initial" : "BRF_next-1");
                                               return signer.signedResponse(config.systemId,
                                                                            challenge,
                                                                            "OK",
                                                                            true,
                                                                            "BRF_next-" + std::to_string(heartbeat));
                                           });
    Client client(config, std::move(fake));
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY"));
    SLB_REQUIRE(client.heartbeatNow());
    SLB_REQUIRE(client.heartbeatNow());
    SLB_REQUIRE_EQ(client.heartbeatCount(), 2U);
}

SLB_TEST("heartbeat: retries one transport loss with the exact token and challenge")
{
    SigningFixture signer;
    auto config = configFor(signer);
    std::string lostChallenge;
    int beatAttempts = 0;
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               const auto challenge = FakeHttp::field(request, "challenge");
                                               if (request.url.ends_with("/init"))
                                                   return signer.signedResponse(config.systemId,
                                                                                challenge,
                                                                                "OK",
                                                                                true,
                                                                                "BRK_initial",
                                                                                "license_key_hash",
                                                                                *detail::sha256Hex("LICENSE-KEY"));
                                               ++beatAttempts;
                                               if (beatAttempts == 1)
                                               {
                                                   lostChallenge = challenge;
                                                   HttpResponse failed;
                                                   failed.error = "simulated lost response";
                                                   return failed;
                                               }
                                               SLB_REQUIRE_EQ(challenge, lostChallenge);
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "session_token"), "BRK_initial");
                                               return signer.signedResponse(config.systemId, challenge, "OK", true, "BRF_after-retry");
                                           });
    Client client(config, std::move(fake));
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY"));
    SLB_REQUIRE(client.heartbeatNow());
    SLB_REQUIRE_EQ(beatAttempts, 2);
}

SLB_TEST("heartbeat: a signed terminal response ends the local session and invokes the hook")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               const auto challenge = FakeHttp::field(request, "challenge");
                                               if (request.url.ends_with("/init"))
                                                   return signer.signedResponse(config.systemId,
                                                                                challenge,
                                                                                "OK",
                                                                                true,
                                                                                "BRK_initial",
                                                                                "license_key_hash",
                                                                                *detail::sha256Hex("LICENSE-KEY"));
                                               return signer.signedResponse(config.systemId,
                                                                            challenge,
                                                                            "KEY_FROZEN",
                                                                            false,
                                                                            {},
                                                                            {},
                                                                            {},
                                                                            "The license key is frozen.");
                                           });
    Client client(config, std::move(fake));
    std::atomic<bool> hookCalled{false};
    client.onHeartbeatFailure([&](const HeartbeatFailure &failure)
                              {
                                  SLB_REQUIRE(failure.response.has_value());
                                  SLB_REQUIRE_EQ(failure.response->code, ResponseCode::KeyFrozen);
                                  hookCalled.store(true);
                              });
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY"));
    const auto beat = client.heartbeatNow();
    SLB_REQUIRE(beat);
    SLB_REQUIRE_EQ(beat->code, ResponseCode::KeyFrozen);
    SLB_REQUIRE(!client.isAuthenticated());
    SLB_REQUIRE(hookCalled.load());
}

SLB_TEST("heartbeat: accepts only the documented unsigned revoked-key terminal exception")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               const auto challenge = FakeHttp::field(request, "challenge");
                                               if (request.url.ends_with("/init"))
                                                   return signer.signedResponse(config.systemId,
                                                                                challenge,
                                                                                "OK",
                                                                                true,
                                                                                "BRK_initial",
                                                                                "license_key_hash",
                                                                                *detail::sha256Hex("LICENSE-KEY"));
                                               return signer.unsignedRevocation(config.systemId, challenge);
                                           });
    Client client(config, std::move(fake));
    std::atomic<bool> sawRevocation{false};
    client.onHeartbeatFailure([&](const HeartbeatFailure &failure)
                              {
                                  sawRevocation.store(failure.response &&
                                                      failure.response->code == ResponseCode::SigningKeyRevoked);
                              });
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY"));
    const auto beat = client.heartbeatNow();
    SLB_REQUIRE(beat);
    SLB_REQUIRE_EQ(beat->code, ResponseCode::SigningKeyRevoked);
    SLB_REQUIRE(sawRevocation.load());
}

SLB_TEST("configuration: refuses to authenticate without a locally pinned signing key")
{
    SigningFixture signer;
    auto config = configFor(signer);
    config.signingPublicKey.clear();
    auto fake = std::make_unique<FakeHttp>([](const FakeHttp::Request &)
                                           { return HttpResponse{}; });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY");
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::Configuration);
}
