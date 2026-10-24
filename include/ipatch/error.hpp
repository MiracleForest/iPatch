// SPDX-License-Identifier: MIT
// iPatch - a fluent, transaction-oriented x86-64 patching library for Windows.
#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace ipatch {

enum class ErrorCode : unsigned {
    ok = 0,
    not_found,
    invalid_argument,
    invalid_pattern,
    unsupported_instruction,
    out_of_range,
    access_denied,
    allocation_failed,
    insufficient_space,
    already_installed,
    not_installed,
    busy,
    verify_failed,
    overlap,
    module_not_found,
    decode_failed,
    relocation_failed,
    thread_suspend_failed,
    system_error,
    internal,
    ambiguous,
};

[[nodiscard]] constexpr std::string_view to_string(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::ok: return "ok";
    case ErrorCode::not_found: return "not_found";
    case ErrorCode::invalid_argument: return "invalid_argument";
    case ErrorCode::invalid_pattern: return "invalid_pattern";
    case ErrorCode::unsupported_instruction: return "unsupported_instruction";
    case ErrorCode::out_of_range: return "out_of_range";
    case ErrorCode::access_denied: return "access_denied";
    case ErrorCode::allocation_failed: return "allocation_failed";
    case ErrorCode::insufficient_space: return "insufficient_space";
    case ErrorCode::already_installed: return "already_installed";
    case ErrorCode::not_installed: return "not_installed";
    case ErrorCode::busy: return "busy";
    case ErrorCode::verify_failed: return "verify_failed";
    case ErrorCode::overlap: return "overlap";
    case ErrorCode::module_not_found: return "module_not_found";
    case ErrorCode::decode_failed: return "decode_failed";
    case ErrorCode::relocation_failed: return "relocation_failed";
    case ErrorCode::thread_suspend_failed: return "thread_suspend_failed";
    case ErrorCode::system_error: return "system_error";
    case ErrorCode::internal: return "internal";
    case ErrorCode::ambiguous: return "ambiguous";
    }
    return "unknown";
}

class Error {
public:
    Error() = default;
    explicit Error(ErrorCode code, std::string message = {})
        : code_(code), message_(std::move(message)) {}

    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    [[nodiscard]] std::string_view message() const noexcept { return message_; }
    [[nodiscard]] const char* what() const noexcept { return message_.c_str(); }
    [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::ok; }
    explicit operator bool() const noexcept { return !ok(); }

    [[nodiscard]] std::string format() const {
        std::string out{to_string(code_)};
        if (!message_.empty()) {
            out += ": ";
            out += message_;
        }
        return out;
    }

private:
    ErrorCode code_{ErrorCode::ok};
    std::string message_{};
};

template <typename T>
using Result = std::expected<T, Error>;

using Status = std::expected<void, Error>;

[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code, std::string message = {}) {
    return std::unexpected(Error{code, std::move(message)});
}

[[nodiscard]] inline std::unexpected<Error> fail(const Error& error) {
    return std::unexpected(error);
}

[[nodiscard]] inline Status success() noexcept {
    return {};
}

} // namespace ipatch
