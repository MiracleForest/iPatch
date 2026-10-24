// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "decoder.hpp"
#include "ipatch/error.hpp"

namespace ipatch::detail {

struct RelocatedInsn {
    std::size_t old_offset{0};
    std::size_t old_length{0};
    std::size_t new_offset{0};
    std::size_t new_length{0};
};

struct Relocation {
    std::vector<std::uint8_t> code;
    std::vector<RelocatedInsn> instructions;
    std::size_t stolen_length{0};
    std::size_t jump_back_offset{0};
};

/// Relocates the prologue at `source` into executable memory at `destination`.
/// Handles RIP-relative operands, short/near jumps, calls, and internal branch
/// targets. `destination` should be within +/-2 GiB of `source` for best
/// results; the function still expands short branches when needed.
[[nodiscard]] Result<Relocation> relocate(const std::uint8_t* source,
                                          std::size_t stolen_length,
                                          std::uint8_t* destination,
                                          std::size_t capacity);

} // namespace ipatch::detail
