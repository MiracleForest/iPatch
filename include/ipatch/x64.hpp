// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

#include "ipatch/config.hpp"

namespace ipatch::x64 {

/// Direct branch mnemonics for Patcher::replace_branch().
enum class Branch : std::uint8_t {
    jo, jno, jb, jae, je, jne, jbe, ja,
    js, jns, jp, jnp, jl, jge, jle, jg, jmp,
    jc = jb, jnae = jb, jnb = jae, jnc = jae,
    jz = je, jnz = jne, jna = jbe, jnbe = ja,
    jpe = jp, jpo = jnp, jnge = jl, jnl = jge,
    jng = jle, jnle = jg
};

/// Named SIMD selectors for CpuContext. Distinct types make register/lane
/// bounds compile-time checks; these are not general-purpose encoder operands.
template <unsigned Index>
struct XmmReg {
    static_assert(Index < 16, "x86-64 has XMM0 through XMM15");
    static constexpr unsigned id = Index;
};

#define IPATCH_XMM(index) inline constexpr XmmReg<index> xmm##index{}
IPATCH_XMM(0); IPATCH_XMM(1); IPATCH_XMM(2); IPATCH_XMM(3);
IPATCH_XMM(4); IPATCH_XMM(5); IPATCH_XMM(6); IPATCH_XMM(7);
IPATCH_XMM(8); IPATCH_XMM(9); IPATCH_XMM(10); IPATCH_XMM(11);
IPATCH_XMM(12); IPATCH_XMM(13); IPATCH_XMM(14); IPATCH_XMM(15);
#undef IPATCH_XMM

/// A general-purpose register.
///
/// `wildcard` registers are only useful while building a search pattern. They
/// emit a dummy low register and mask the register bits, so `.cmp(any32, 6)`
/// matches `cmp <any 32-bit register>, 6`.
struct Reg {
    std::uint8_t id{0};
    std::uint8_t size{8};
    bool wildcard{false};

    [[nodiscard]] constexpr bool valid() const noexcept { return size == 1 || size == 2 || size == 4 || size == 8; }
    [[nodiscard]] constexpr bool is_extended() const noexcept { return (id & 8u) != 0; }
    [[nodiscard]] constexpr std::uint8_t low3() const noexcept { return id & 7u; }
};

/// A simple [base + disp] memory operand. SIB/index addressing is intentionally
/// left out of the fluent builder; raw signatures cover exotic cases.
struct Mem {
    Reg base{};
    std::int32_t disp{0};
    std::uint8_t size{0}; // operand size; 0 = infer from the register operand
    bool wildcard_base{false};
    bool wildcard_disp{false};
};

[[nodiscard]] constexpr Mem mem(Reg base, std::int32_t disp = 0, std::uint8_t size = 0) noexcept {
    return Mem{base, disp, size, false, false};
}

[[nodiscard]] constexpr Mem any_mem(std::uint8_t size = 0, std::uint8_t base_size = 8) noexcept {
    return Mem{Reg{0, base_size, true}, 0, size, true, true};
}

[[nodiscard]] constexpr Mem operator+(Reg base, std::int32_t disp) noexcept {
    return mem(base, disp);
}

[[nodiscard]] constexpr Mem operator-(Reg base, std::int32_t disp) noexcept {
    return mem(base, -disp);
}

#define IPATCH_REG(name, index, width) \
    inline constexpr Reg name{index, width, false}

// 64-bit
IPATCH_REG(rax, 0, 8);
IPATCH_REG(rcx, 1, 8);
IPATCH_REG(rdx, 2, 8);
IPATCH_REG(rbx, 3, 8);
IPATCH_REG(rsp, 4, 8);
IPATCH_REG(rbp, 5, 8);
IPATCH_REG(rsi, 6, 8);
IPATCH_REG(rdi, 7, 8);
IPATCH_REG(r8, 8, 8);
IPATCH_REG(r9, 9, 8);
IPATCH_REG(r10, 10, 8);
IPATCH_REG(r11, 11, 8);
IPATCH_REG(r12, 12, 8);
IPATCH_REG(r13, 13, 8);
IPATCH_REG(r14, 14, 8);
IPATCH_REG(r15, 15, 8);

// 32-bit
IPATCH_REG(eax, 0, 4);
IPATCH_REG(ecx, 1, 4);
IPATCH_REG(edx, 2, 4);
IPATCH_REG(ebx, 3, 4);
IPATCH_REG(esp, 4, 4);
IPATCH_REG(ebp, 5, 4);
IPATCH_REG(esi, 6, 4);
IPATCH_REG(edi, 7, 4);
IPATCH_REG(r8d, 8, 4);
IPATCH_REG(r9d, 9, 4);
IPATCH_REG(r10d, 10, 4);
IPATCH_REG(r11d, 11, 4);
IPATCH_REG(r12d, 12, 4);
IPATCH_REG(r13d, 13, 4);
IPATCH_REG(r14d, 14, 4);
IPATCH_REG(r15d, 15, 4);

// 16-bit
IPATCH_REG(ax, 0, 2);
IPATCH_REG(cx, 1, 2);
IPATCH_REG(dx, 2, 2);
IPATCH_REG(bx, 3, 2);
IPATCH_REG(sp, 4, 2);
IPATCH_REG(bp, 5, 2);
IPATCH_REG(si, 6, 2);
IPATCH_REG(di, 7, 2);
IPATCH_REG(r8w, 8, 2);
IPATCH_REG(r9w, 9, 2);
IPATCH_REG(r10w, 10, 2);
IPATCH_REG(r11w, 11, 2);
IPATCH_REG(r12w, 12, 2);
IPATCH_REG(r13w, 13, 2);
IPATCH_REG(r14w, 14, 2);
IPATCH_REG(r15w, 15, 2);

// 8-bit
IPATCH_REG(al, 0, 1);
IPATCH_REG(cl, 1, 1);
IPATCH_REG(dl, 2, 1);
IPATCH_REG(bl, 3, 1);
IPATCH_REG(spl, 4, 1);
IPATCH_REG(bpl, 5, 1);
IPATCH_REG(sil, 6, 1);
IPATCH_REG(dil, 7, 1);
IPATCH_REG(r8b, 8, 1);
IPATCH_REG(r9b, 9, 1);
IPATCH_REG(r10b, 10, 1);
IPATCH_REG(r11b, 11, 1);
IPATCH_REG(r12b, 12, 1);
IPATCH_REG(r13b, 13, 1);
IPATCH_REG(r14b, 14, 1);
IPATCH_REG(r15b, 15, 1);

// Wildcard registers for signature building.
inline constexpr Reg any8{0, 1, true};
inline constexpr Reg any16{0, 2, true};
inline constexpr Reg any32{0, 4, true};
inline constexpr Reg any64{0, 8, true};

#undef IPATCH_REG

} // namespace ipatch::x64
