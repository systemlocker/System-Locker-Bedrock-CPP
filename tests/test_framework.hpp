#pragma once

#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace syslocker::bedrock::test
{
    struct TestCase
    {
        const char *name;
        std::function<void()> function;
    };

    inline std::vector<TestCase> &registry()
    {
        static std::vector<TestCase> tests;
        return tests;
    }

    struct Registrar
    {
        Registrar(const char *name, std::function<void()> function)
        {
            registry().push_back(TestCase{name, std::move(function)});
        }
    };

    inline void require(bool condition, const char *expression, const char *file, int line)
    {
        if (!condition)
        {
            std::ostringstream message;
            message << file << ':' << line << ": requirement failed: " << expression;
            throw std::runtime_error(message.str());
        }
    }
}

#define SLB_JOIN_INNER(a, b) a##b
#define SLB_JOIN(a, b) SLB_JOIN_INNER(a, b)
#define SLB_TEST(name)                                                                                                  \
    static void SLB_JOIN(test_, __LINE__)();                                                                            \
    static ::syslocker::bedrock::test::Registrar SLB_JOIN(registrar_, __LINE__)(name, SLB_JOIN(test_, __LINE__));       \
    static void SLB_JOIN(test_, __LINE__)()
#define SLB_REQUIRE(expression) ::syslocker::bedrock::test::require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)
#define SLB_REQUIRE_EQ(left, right) SLB_REQUIRE((left) == (right))
