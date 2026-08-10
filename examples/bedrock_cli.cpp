#include "syslocker/bedrock.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace
{
    std::string environment(const char *name)
    {
        const char *value = std::getenv(name);
        return value == nullptr ? std::string{} : std::string(value);
    }

    void usage()
    {
        std::cerr << "Usage: systemlocker_bedrock_cli --system ID --public-key BASE64URL [--watch]\n"
                     "Credentials are read from SYSLOCKER_BEDROCK_LICENSE_KEY, or from both\n"
                     "SYSLOCKER_BEDROCK_USERNAME and SYSLOCKER_BEDROCK_PASSWORD.\n";
    }
}

int main(int argc, char **argv)
{
    using namespace syslocker::bedrock;

    Config config;
    config.hwid = environment("SYSLOCKER_BEDROCK_HWID");
    if (config.hwid.empty())
        config.hwid = "bedrock-cpp-cli";
    config.version = environment("SYSLOCKER_BEDROCK_VERSION");
    if (config.version.empty())
        config.version = "bypass";

    std::string publicKey;
    bool watch = false;
    for (int index = 1; index < argc; ++index)
    {
        const std::string argument = argv[index];
        if (argument == "--system" && index + 1 < argc)
            config.systemId = argv[++index];
        else if (argument == "--public-key" && index + 1 < argc)
            publicKey = argv[++index];
        else if (argument == "--watch")
            watch = true;
        else
        {
            usage();
            return 2;
        }
    }

    if (config.systemId.empty() || publicKey.empty())
    {
        usage();
        return 2;
    }
    config.signingPublicKey = publicKey;
    config.automaticHeartbeats = watch;

    Client client(config);
    client.onHeartbeatFailure([](const HeartbeatFailure &failure)
                              { std::cerr << "Bedrock session ended: " << failure.error.message << '\n'; });

    const std::string licenseKey = environment("SYSLOCKER_BEDROCK_LICENSE_KEY");
    const std::string username = environment("SYSLOCKER_BEDROCK_USERNAME");
    const std::string password = environment("SYSLOCKER_BEDROCK_PASSWORD");
    Result<AuthenticationResult> result = !licenseKey.empty()
                                              ? client.authenticateWithKey(licenseKey)
                                              : client.authenticateWithPassword(username, password);
    if (!result)
    {
        std::cerr << "Bedrock verification failed: " << result.error().message << '\n';
        return 1;
    }

    std::cout << "Verified response: " << result->response.responseCode << "\n"
              << "Message: " << result->response.humanResponse << '\n';
    if (!result->sessionStarted)
        return 3;

    if (watch)
    {
        std::cout << "Session active; press Ctrl+C to exit.\n";
        while (client.isAuthenticated())
            std::this_thread::sleep_for(std::chrono::seconds(1));
        return 4;
    }

    client.shutdown();
    return 0;
}
