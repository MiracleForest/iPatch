// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>

#include "ipatch/config.hpp"

namespace ipatch {

/// A half-open byte range [begin, end).
struct Range {
    std::byte* begin{nullptr};
    std::byte* end{nullptr};

    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return begin && end && end > begin
                   ? static_cast<std::size_t>(end - begin)
                   : 0;
    }

    [[nodiscard]] constexpr bool empty() const noexcept { return size() == 0; }

    [[nodiscard]] constexpr bool contains(const void* address) const noexcept {
        const auto* p = static_cast<const std::byte*>(address);
        return begin && p >= begin && p < end;
    }

    [[nodiscard]] static constexpr Range from(void* address, std::size_t length) noexcept {
        auto* p = static_cast<std::byte*>(address);
        return {p, p ? p + length : nullptr};
    }

    [[nodiscard]] constexpr Range subrange(std::size_t offset, std::size_t length) const noexcept {
        if (!begin || offset > size()) return {};
        const std::size_t available = size() - offset;
        if (length > available) length = available;
        return {begin + offset, begin + offset + length};
    }
};

} // namespace ipatch
