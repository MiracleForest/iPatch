// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "ipatch/error.hpp"

namespace ipatch::detail {

// Address arithmetic is integer arithmetic, not C++ array pointer arithmetic.
// In particular, negating PTRDIFF_MIN directly would be undefined behavior.
inline Result<std::byte*> offset_address(std::byte* address, std::ptrdiff_t offset) {
    if (!address) return fail(ErrorCode::invalid_argument, "address is null");
    auto value = reinterpret_cast<std::uintptr_t>(address);
    if (offset >= 0) {
        const auto amount = static_cast<std::uintptr_t>(offset);
        if (amount > std::numeric_limits<std::uintptr_t>::max() - value)
            return fail(ErrorCode::out_of_range, "address overflow");
        value += amount;
    } else {
        const auto amount = static_cast<std::uintptr_t>(-(offset + 1)) + 1;
        if (amount >= value) return fail(ErrorCode::out_of_range, "address underflow or null result");
        value -= amount;
    }
    return reinterpret_cast<std::byte*>(value);
}

inline Result<std::ptrdiff_t> add_offsets(std::ptrdiff_t a, std::ptrdiff_t b) {
    if ((b > 0 && a > std::numeric_limits<std::ptrdiff_t>::max() - b) ||
        (b < 0 && a < std::numeric_limits<std::ptrdiff_t>::min() - b))
        return fail(ErrorCode::out_of_range, "offset overflow");
    return a + b;
}

} // namespace ipatch::detail
