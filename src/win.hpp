// SPDX-License-Identifier: MIT
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <format>
#include <memory>
#include <string>

namespace ipatch::detail {

template <typename T>
[[nodiscard]] constexpr T align_up(T value, T alignment) noexcept {
    return (value + alignment - 1) & ~(alignment - 1);
}

template <typename T>
[[nodiscard]] constexpr T align_down(T value, T alignment) noexcept {
    return value & ~(alignment - 1);
}

struct HandleCloser {
    void operator()(void* handle) const noexcept {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(static_cast<HANDLE>(handle));
        }
    }
};

using UniqueHandle = std::unique_ptr<void, HandleCloser>;

[[nodiscard]] inline UniqueHandle make_handle(HANDLE handle) noexcept {
    return UniqueHandle{handle == INVALID_HANDLE_VALUE ? nullptr : handle};
}

[[nodiscard]] inline std::string win32_message(DWORD error) {
    if (error == 0) return {};
    LPSTR buffer = nullptr;
    const DWORD length = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
    std::string message;
    if (length && buffer) {
        message.assign(buffer, length);
        while (!message.empty() && (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
            message.pop_back();
        }
    }
    if (buffer) ::LocalFree(buffer);
    if (message.empty()) message = "Win32 error " + std::to_string(error);
    return message;
}

[[nodiscard]] inline std::string hex(std::uint64_t value) {
    return std::format("0x{:X}", value);
}

} // namespace ipatch::detail
