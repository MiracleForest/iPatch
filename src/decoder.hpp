// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>

namespace ipatch::detail {

enum class RelKind : std::uint8_t {
    none = 0,
    jmp8,
    jmp32,
    jcc8,
    jcc32,
    call32,
    loop8,
};

struct Insn {
    std::uint8_t length{0};
    std::uint8_t opcode_map{0}; // 0 = one-byte opcode, 1 = 0F, 2 = 0F38, 3 = 0F3A
    std::uint8_t opcode{0};

    bool has_modrm{false};
    std::uint8_t modrm_offset{0};
    std::uint8_t sib_offset{0};

    bool rip_relative{false};
    std::uint8_t disp_offset{0};
    std::uint8_t disp_size{0};

    std::uint8_t imm_offset{0};
    std::uint8_t imm_size{0};

    RelKind rel{RelKind::none};
    std::uint8_t rel_offset{0};
    std::uint8_t rel_size{0};
    std::uint8_t condition{0}; // for jcc

    bool is_ret{false};
    bool is_jmp{false};
    bool is_call{false};
    bool is_int3{false};
    bool is_nop{false};
    bool is_padding{false};
    bool valid{false};

    [[nodiscard]] bool is_branch() const noexcept {
        return rel != RelKind::none;
    }

    [[nodiscard]] std::int64_t relative_target(const std::uint8_t* code,
                                               std::uint64_t instruction_address) const noexcept;
    [[nodiscard]] std::int64_t rip_target(const std::uint8_t* code,
                                          std::uint64_t instruction_address) const noexcept;
};

/// Decodes exactly one x86-64 instruction. Returns false for truncated or
/// unsupported encodings. The decoder is deliberately conservative: unknown
/// vector encodings are rejected instead of risking a wrong length.
[[nodiscard]] bool decode_one(const std::uint8_t* code, std::size_t available,
                              Insn& out) noexcept;

} // namespace ipatch::detail
