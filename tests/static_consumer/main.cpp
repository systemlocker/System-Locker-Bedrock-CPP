#include <syslocker/bedrock.hpp>

#include <utility>

int main()
{
    syslocker::bedrock::Config config;
    config.systemId = "staticbuild000000001";
    config.automaticHeartbeats = false;

    syslocker::bedrock::Client client(std::move(config));
    client.shutdown();
    return 0;
}
