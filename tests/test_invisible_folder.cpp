#include "test_framework.hpp"

#include "fake_http.hpp"
#include "signing_fixture.hpp"
#include "syslocker/bedrock.hpp"

#include <map>
#include <optional>

using namespace syslocker::bedrock;
using namespace syslocker::bedrock::test;

namespace
{
    HttpResponse metadataResponse()
    {
        HttpResponse response;
        response.status = 200;
        response.body = R"({"data":{"file":{"id":"file-id","reference_id":"release-1","name":"release.bin","mime_type":"application/octet-stream","size":42,"downloads":8,"uploaded_at":"2026-08-14T12:00:00Z","permission_type_id":60},"metadata":{"__revisions":{"value":"7","created_at":"2026-08-14T12:00:00Z"},"channel":{"value":"stable","created_at":null}}}})";
        return response;
    }
}

SLB_TEST("initialization: requests variables and an Invisible Folder token only when asked")
{
    SigningFixture signer;
    auto config = configFor(signer);
    const auto identityHash = detail::sha256Hex("LICENSE-KEY");
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "init-if"), "true");
                                               int variables = 0;
                                               for (const auto &[name, value] : request.fields)
                                               {
                                                   if (name == "variables[]" && (value == "welcome" || value == "missing"))
                                                       ++variables;
                                               }
                                               SLB_REQUIRE_EQ(variables, 2);
                                               return signer.signedResponse(
                                                   config.systemId,
                                                   FakeHttp::field(request, "challenge"),
                                                   "OK", true, "BRK_initial", "license_key_hash", *identityHash, {}, 0,
                                                   "if_token_initial_1234567890",
                                                   {{"missing", std::nullopt}, {"welcome", std::string("hello")}});
                                           });

    Client client(config, std::move(fake));
    InitializationOptions options;
    options.requestInvisibleFolderToken = true;
    options.variables = {"welcome", "missing"};
    const auto auth = client.authenticateWithKey("LICENSE-KEY", options);
    SLB_REQUIRE(auth);
    SLB_REQUIRE(auth->response.invisibleFolderToken.has_value());
    SLB_REQUIRE_EQ(auth->response.variables.at("welcome").value(), std::string("hello"));
    SLB_REQUIRE(!auth->response.variables.at("missing").has_value());
    SLB_REQUIRE(client.invisibleFolder().hasToken());
}

SLB_TEST("heartbeat: can request and cache a fresh Invisible Folder token")
{
    SigningFixture signer;
    auto config = configFor(signer);
    const auto identityHash = detail::sha256Hex("LICENSE-KEY");
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               const auto challenge = FakeHttp::field(request, "challenge");
                                               if (request.url.ends_with("/init"))
                                                   return signer.signedResponse(config.systemId, challenge, "OK", true, "BRK_initial",
                                                                                "license_key_hash", *identityHash);
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "init-if"), "true");
                                               return signer.signedResponse(config.systemId, challenge, "OK", true, "BRF_next", {}, {}, {}, 0,
                                                                            "if_token_heartbeat_1234567890");
                                           });

    Client client(config, std::move(fake));
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY"));
    const auto beat = client.heartbeatNow({true});
    SLB_REQUIRE(beat);
    SLB_REQUIRE_EQ(*beat->invisibleFolderToken, std::string("if_token_heartbeat_1234567890"));
    SLB_REQUIRE(client.invisibleFolder().hasToken());
}

SLB_TEST("initialization: rejects variables returned on a rejected initialization")
{
    SigningFixture signer;
    auto config = configFor(signer);
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               return signer.signedResponse(config.systemId, FakeHttp::field(request, "challenge"),
                                                                            "INVALID_KEY", false, {}, {}, {}, {}, 0,
                                                                            std::nullopt, {{"welcome", std::string("not allowed")}});
                                           });
    Client client(config, std::move(fake));
    const auto auth = client.authenticateWithKey("LICENSE-KEY", {.variables = {"welcome"}});
    SLB_REQUIRE(!auth);
    SLB_REQUIRE_EQ(auth.error().kind, ErrorKind::InvalidPayload);
}

SLB_TEST("invisible folder: metadata sends API and Advanced-token credentials together")
{
    SigningFixture signer;
    auto config = configFor(signer);
    config.invisibleFolderApiKey = "IFK_metadata_key";
    const auto identityHash = detail::sha256Hex("LICENSE-KEY");
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               if (request.method == "POST")
                                                   return signer.signedResponse(config.systemId, FakeHttp::field(request, "challenge"), "OK", true,
                                                                                "BRK_initial", "license_key_hash", *identityHash, {}, 0,
                                                                                "if_token_metadata_1234567890");
                                               SLB_REQUIRE_EQ(request.method, std::string("GET"));
                                               SLB_REQUIRE(request.url.find("/api/v1/files/release-1/metadata?keys[]=__revisions&keys[]=channel") != std::string::npos);
                                               SLB_REQUIRE_EQ(FakeHttp::header(request, "X-Api-Key"), std::string("IFK_metadata_key"));
                                               SLB_REQUIRE_EQ(FakeHttp::header(request, "X-Invisiblefolder-Token"), std::string("if_token_metadata_1234567890"));
                                               return metadataResponse();
                                           });

    Client client(config, std::move(fake));
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY", {.requestInvisibleFolderToken = true}));
    const auto metadata = client.invisibleFolder().metadata("release-1", {"__revisions", "channel"});
    SLB_REQUIRE(metadata);
    SLB_REQUIRE_EQ(metadata->file.name, std::string("release.bin"));
    SLB_REQUIRE_EQ(metadata->values.at("__revisions").value, std::string("7"));
    SLB_REQUIRE(!metadata->values.at("channel").createdAt.has_value());
}

SLB_TEST("invisible folder: downloadIfNew skips equal revisions and downloads newer bytes")
{
    SigningFixture signer;
    auto config = configFor(signer);
    const auto identityHash = detail::sha256Hex("LICENSE-KEY");
    int downloads = 0;
    auto fake = std::make_unique<FakeHttp>([&](const FakeHttp::Request &request)
                                           {
                                               if (request.url.ends_with("/init"))
                                                   return signer.signedResponse(config.systemId, FakeHttp::field(request, "challenge"), "OK", true,
                                                                                "BRK_initial", "license_key_hash", *identityHash, {}, 0,
                                                                                "if_token_update_1234567890");
                                               if (request.method == "GET")
                                                   return metadataResponse();
                                               ++downloads;
                                               SLB_REQUIRE_EQ(FakeHttp::field(request, "invisiblefolder_token"), std::string("if_token_update_1234567890"));
                                               HttpResponse download;
                                               download.status = 200;
                                               download.body = "new release bytes";
                                               return download;
                                           });

    Client client(config, std::move(fake));
    SLB_REQUIRE(client.authenticateWithKey("LICENSE-KEY", {.requestInvisibleFolderToken = true}));
    const auto current = client.invisibleFolder().downloadIfNew("release-1", "7");
    SLB_REQUIRE(current);
    SLB_REQUIRE(!current->downloaded);
    SLB_REQUIRE_EQ(downloads, 0);

    const auto updated = client.invisibleFolder().downloadIfNew("release-1", "6");
    SLB_REQUIRE(updated);
    SLB_REQUIRE(updated->downloaded);
    SLB_REQUIRE(updated->bytes.has_value());
    SLB_REQUIRE_EQ(std::string(updated->bytes->begin(), updated->bytes->end()), std::string("new release bytes"));
    SLB_REQUIRE_EQ(downloads, 1);
}
