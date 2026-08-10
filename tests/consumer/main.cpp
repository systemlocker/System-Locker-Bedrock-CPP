#include <syslocker/bedrock.hpp>

int main()
{
    syslocker::bedrock::Config config;
    return config.baseUrl == "https://systemlocker.net" ? 0 : 1;
}
