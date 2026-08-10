#include "syslocker/bedrock.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace
{
    std::string environment(const char *name)
    {
        const char *value = std::getenv(name);
        return value == nullptr ? std::string{} : std::string(value);
    }
}

int main()
{
    using namespace syslocker::bedrock;

    const std::string system = environment("SYSLOCKER_BEDROCK_SYSTEM_ID");
    const std::string publicKey = environment("SYSLOCKER_BEDROCK_PUBLIC_KEY");
    const std::string licenseKey = environment("SYSLOCKER_BEDROCK_LICENSE_KEY");
    if (system.empty() || publicKey.empty() || licenseKey.empty())
    {
        std::cerr << "Set SYSLOCKER_BEDROCK_SYSTEM_ID, SYSLOCKER_BEDROCK_PUBLIC_KEY, "
                     "and SYSLOCKER_BEDROCK_LICENSE_KEY.\n";
        return 2;
    }

    Config config;
    config.systemId = system;
    config.hwid = environment("SYSLOCKER_BEDROCK_HWID");
    if (config.hwid.empty())
        config.hwid = "bedrock-cpp-live-test";
    config.version = environment("SYSLOCKER_BEDROCK_VERSION");
    if (config.version.empty())
        config.version = "bypass";
    config.automaticHeartbeats = false;
    config.signingPublicKey = publicKey;

    Client client(config);
    const auto result = client.authenticateWithKey(licenseKey);
    if (!result)
    {
        std::cerr << "Live verification failed: " << result.error().message << '\n';
        return 1;
    }

    std::cout << "Verified signed Bedrock response: " << result->response.responseCode << '\n';
    std::cout << "Session started: " << (result->sessionStarted ? "yes" : "no") << '\n';
    client.shutdown();
    return result->response.authed ? 0 : 3;
}
