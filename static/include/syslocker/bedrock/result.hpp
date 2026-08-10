#pragma once

#include <optional>
#include <string>
#include <utility>

namespace syslocker::bedrock
{
    enum class ErrorKind
    {
        Configuration,
        Transport,
        UnsignedResponse,
        InvalidSignature,
        InvalidPayload,
        FreshnessViolation,
        SessionTerminated,
        LocalFailure,
    };

    struct Error
    {
        ErrorKind kind = ErrorKind::LocalFailure;
        std::string message;
    };

    template <class T>
    class Result
    {
    public:
        Result(T value) : value_(std::move(value)) {}

        static Result fail(ErrorKind kind, std::string message)
        {
            Result result;
            result.error_ = Error{kind, std::move(message)};
            return result;
        }

        explicit operator bool() const noexcept { return value_.has_value(); }
        bool ok() const noexcept { return value_.has_value(); }

        T &operator*() { return *value_; }
        const T &operator*() const { return *value_; }
        T *operator->() { return &*value_; }
        const T *operator->() const { return &*value_; }

        const Error &error() const noexcept { return *error_; }

    private:
        Result() = default;
        std::optional<T> value_;
        std::optional<Error> error_;
    };
}
