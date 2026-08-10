#include "test_framework.hpp"

#include <cstdio>
#include <exception>

int main()
{
    int passed = 0;
    int failed = 0;
    for (const auto &test : syslocker::bedrock::test::registry())
    {
        std::fprintf(stderr, "[ RUN  ] %s\n", test.name);
        try
        {
            test.function();
            ++passed;
            std::fprintf(stderr, "[  OK  ] %s\n", test.name);
        }
        catch (const std::exception &error)
        {
            ++failed;
            std::fprintf(stderr, "[ FAIL ] %s: %s\n", test.name, error.what());
        }
        catch (...)
        {
            ++failed;
            std::fprintf(stderr, "[ FAIL ] %s: unknown exception\n", test.name);
        }
    }
    std::fprintf(stderr, "\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
