// SPDX-License-Identifier: MIT
#include "emitter.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>

// Xbyak is header-only.  Disable exceptions for this translation unit so an
// invalid operand is reported through GetError() on every supported compiler.
#define XBYAK_NO_EXCEPTION
#include <xbyak/xbyak.h>
#undef XBYAK_NO_EXCEPTION

namespace ipatch::detail {
namespace {

[[nodiscard]] bool fits_i8(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int8_t>::min() && value <= std::numeric_limits<std::int8_t>::max();
}

[[nodiscard]] bool fits_i32(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int32_t>::min() && value <= std::numeric_limits<std::int32_t>::max();
}

[[nodiscard]] bool valid_size(std::uint8_t size) noexcept { return size == 1 || size == 2 || size == 4 || size == 8; }

[[nodiscard]] bool needs_rex8(x64::Reg reg) noexcept {
    // spl/bpl/sil/dil need a REX prefix. The public register set has no
    // ah/ch/dh/bh, so id >= 4 always means the low-byte variants.
    return reg.size == 1 && reg.id >= 4;
}

[[nodiscard]] Xbyak::Reg xbyak_reg(x64::Reg reg) noexcept {
    switch (reg.size) {
    case 1:
        return Xbyak::Reg8(reg.id);
    case 2:
        return Xbyak::Reg16(reg.id);
    case 4:
        return Xbyak::Reg32(reg.id);
    default:
        return Xbyak::Reg64(reg.id);
    }
}

[[nodiscard]] Xbyak::Address xbyak_mem(const x64::Mem& mem, std::uint8_t size) noexcept {
    auto value = Xbyak::util::ptr[Xbyak::Reg64(mem.base.id) + mem.disp];
    return size == 0 ? value : value.changeBit(static_cast<int>(size) * 8);
}

[[nodiscard]] bool xbyak_mem_supported(const x64::Mem& mem) noexcept {
    return !mem.wildcard_base && !mem.wildcard_disp && !mem.base.wildcard && mem.base.valid() && mem.base.size == 8;
}

// Assemble `fn` into a small caller-owned buffer and append the result to the
// emitter.  The buffer keeps Xbyak allocation-free for these short forms and
// makes a failed instruction transactional, just like the pattern encoder.
template <typename Fn>
bool encode_with_xbyak(Emitter& e, Fn&& fn) {
    std::array<std::uint8_t, 128> buffer{};
    Xbyak::ClearError();
    Xbyak::CodeGenerator assembler(buffer.size(), buffer.data());
    std::forward<Fn>(fn)(assembler);
    if (Xbyak::GetError() != Xbyak::ERR_NONE || assembler.getSize() == 0) return false;
    e.append(std::span<const std::uint8_t>(assembler.getCode(), assembler.getSize()));
    return true;
}

[[nodiscard]] bool xbyak_mov_reg_reg(Emitter& e, x64::Reg dst, x64::Reg src) {
    return encode_with_xbyak(e, [dst, src](Xbyak::CodeGenerator& a) { a.mov(xbyak_reg(dst), xbyak_reg(src)); });
}

[[nodiscard]] bool xbyak_mov_reg_imm(Emitter& e, x64::Reg dst, std::int64_t imm) {
    return encode_with_xbyak(e, [dst, imm](Xbyak::CodeGenerator& a) { a.mov(xbyak_reg(dst), imm); });
}

[[nodiscard]] bool xbyak_mov_reg_mem(Emitter& e, x64::Reg dst, const x64::Mem& src) {
    if (!xbyak_mem_supported(src)) return false;
    return encode_with_xbyak(e, [dst, src](Xbyak::CodeGenerator& a) {
        a.mov(xbyak_reg(dst), xbyak_mem(src, dst.size));
    });
}

[[nodiscard]] bool xbyak_mov_mem_reg(Emitter& e, const x64::Mem& dst, x64::Reg src) {
    if (!xbyak_mem_supported(dst)) return false;
    return encode_with_xbyak(e, [dst, src](Xbyak::CodeGenerator& a) {
        a.mov(xbyak_mem(dst, src.size), xbyak_reg(src));
    });
}

[[nodiscard]] bool xbyak_mov_mem_imm(Emitter& e, const x64::Mem& dst, std::int32_t imm, std::uint8_t size) {
    if (!xbyak_mem_supported(dst)) return false;
    return encode_with_xbyak(e, [dst, imm, size](Xbyak::CodeGenerator& a) { a.mov(xbyak_mem(dst, size), imm); });
}

[[nodiscard]] bool xbyak_lea(Emitter& e, x64::Reg dst, const x64::Mem& src) {
    if (!xbyak_mem_supported(src)) return false;
    return encode_with_xbyak(e, [dst, src](Xbyak::CodeGenerator& a) { a.lea(xbyak_reg(dst), xbyak_mem(src, 0)); });
}

[[nodiscard]] bool xbyak_alu_reg_reg(Emitter& e, AluOp op, x64::Reg dst, x64::Reg src) {
    return encode_with_xbyak(e, [op, dst, src](Xbyak::CodeGenerator& a) {
        const auto lhs = xbyak_reg(dst);
        const auto rhs = xbyak_reg(src);
        switch (op) {
        case AluOp::add:
            a.add(lhs, rhs);
            break;
        case AluOp::or_:
            a.or_(lhs, rhs);
            break;
        case AluOp::and_:
            a.and_(lhs, rhs);
            break;
        case AluOp::sub:
            a.sub(lhs, rhs);
            break;
        case AluOp::xor_:
            a.xor_(lhs, rhs);
            break;
        case AluOp::cmp:
            a.cmp(lhs, rhs);
            break;
        }
    });
}

[[nodiscard]] bool xbyak_alu_reg_imm(Emitter& e, AluOp op, x64::Reg dst, std::int32_t imm) {
    return encode_with_xbyak(e, [op, dst, imm](Xbyak::CodeGenerator& a) {
        const auto reg   = xbyak_reg(dst);
        const auto value = static_cast<std::int64_t>(imm);
        switch (op) {
        case AluOp::add:
            a.add(reg, static_cast<std::int32_t>(value));
            break;
        case AluOp::or_:
            a.or_(reg, static_cast<std::int32_t>(value));
            break;
        case AluOp::and_:
            a.and_(reg, static_cast<std::int32_t>(value));
            break;
        case AluOp::sub:
            a.sub(reg, static_cast<std::int32_t>(value));
            break;
        case AluOp::xor_:
            a.xor_(reg, static_cast<std::int32_t>(value));
            break;
        case AluOp::cmp:
            a.cmp(reg, static_cast<std::int32_t>(value));
            break;
        }
    });
}

[[nodiscard]] bool xbyak_test_reg_reg(Emitter& e, x64::Reg dst, x64::Reg src) {
    return encode_with_xbyak(e, [dst, src](Xbyak::CodeGenerator& a) { a.test(xbyak_reg(dst), xbyak_reg(src)); });
}

[[nodiscard]] bool xbyak_test_reg_imm(Emitter& e, x64::Reg dst, std::int32_t imm) {
    return encode_with_xbyak(e, [dst, imm](Xbyak::CodeGenerator& a) {
        a.test(xbyak_reg(dst), static_cast<std::int64_t>(imm));
    });
}

[[nodiscard]] bool xbyak_inc_dec(Emitter& e, x64::Reg reg, bool increment) {
    return encode_with_xbyak(e, [reg, increment](Xbyak::CodeGenerator& a) {
        if (increment) {
            a.inc(xbyak_reg(reg));
        } else {
            a.dec(xbyak_reg(reg));
        }
    });
}

[[nodiscard]] bool xbyak_push_pop(Emitter& e, x64::Reg reg, bool push) {
    return encode_with_xbyak(e, [reg, push](Xbyak::CodeGenerator& a) {
        if (push) {
            a.push(xbyak_reg(reg));
        } else {
            a.pop(xbyak_reg(reg));
        }
    });
}

// Write mode is encoded by Xbyak. The custom encoder below is only
// used to produce wildcard masks for pattern mode.
#define IPATCH_XBYAK_OR_FAIL(e, expr, message)                                                                         \
    do {                                                                                                               \
        if (!(e).pattern_mode()) {                                                                                     \
            if (expr) return;                                                                                          \
            (e).fail(message);                                                                                         \
            return;                                                                                                    \
        }                                                                                                              \
    } while (false)

void emit_reg_prefixes(Emitter& e, std::uint8_t size, bool rex_r, bool rex_b, bool force_rex) {
    if (size == 2) e.byte(0x66);
    e.rex(size == 8, rex_r, false, rex_b, force_rex);
}

void emit_alu_imm(Emitter& e, AluOp op, x64::Reg dst, std::int32_t imm) {
    if (!valid_size(dst.size)) {
        e.fail("invalid register width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_alu_reg_imm(e, op, dst, imm), "Xbyak could not encode ALU immediate");
    const auto digit = static_cast<std::uint8_t>(op);
    const bool rex8  = needs_rex8(dst);
    emit_reg_prefixes(e, dst.size, false, dst.id >= 8, rex8);

    if (dst.size == 1) {
        e.byte(0x80);
        e.modrm(3, digit, dst.low3(), false, dst.wildcard);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint8_t>(imm)), 1, false);
        return;
    }

    if (fits_i8(imm)) {
        e.byte(0x83);
        e.modrm(3, digit, dst.low3(), false, dst.wildcard);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint8_t>(imm)), 1, false);
        return;
    }

    if (dst.size == 8 && !fits_i32(imm)) {
        e.fail("64-bit ALU immediate does not fit in 32 bits");
        return;
    }

    e.byte(0x81);
    e.modrm(3, digit, dst.low3(), false, dst.wildcard);
    const std::uint8_t imm_size = dst.size == 2 ? 2 : 4;
    e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(imm)), imm_size, false);
}

} // namespace

void emit_prefixes(Emitter& e, std::uint8_t operand_size, bool rex_r, bool rex_b, bool force_rex) {
    emit_reg_prefixes(e, operand_size, rex_r, rex_b, force_rex);
}

void emit_modrm_mem(Emitter& e, x64::Reg reg, const x64::Mem& mem) {
    if (!reg.valid() && !reg.wildcard) {
        e.fail("invalid register");
        return;
    }
    if (mem.wildcard_base) {
        // Generic [reg + disp32]. This deliberately does not match SIB or
        // RIP-relative encodings; use raw signatures for those.
        e.modrm(2, reg.low3(), 0, reg.wildcard, true);
        e.displacement(0, 4, true);
        return;
    }
    if (!mem.base.valid() && !mem.base.wildcard) {
        e.fail("invalid memory base register");
        return;
    }

    const std::uint8_t low           = mem.base.low3();
    std::uint8_t       mod           = 0;
    const bool         wildcard_disp = mem.wildcard_disp;
    if (wildcard_disp) {
        mod = 2;
    } else if (mem.disp == 0 && low != 5) {
        mod = 0;
    } else if (fits_i8(mem.disp)) {
        mod = 1;
    } else {
        mod = 2;
    }

    const bool         has_sib = low == 4;
    const std::uint8_t rm      = has_sib ? 4 : low;
    e.modrm(mod, reg.low3(), rm, reg.wildcard, mem.wildcard_base);

    if (has_sib) {
        // scale=0, index=4 (none), base=low
        e.sib(0, 4, low, false, mem.wildcard_base);
    }

    if (wildcard_disp) {
        e.displacement(0, 4, true);
    } else if (mod == 1) {
        e.displacement(mem.disp, 1, false);
    } else if (mod == 2) {
        e.displacement(mem.disp, 4, false);
    } else if (has_sib && low == 5) {
        // mod=0 + SIB base=5 means disp32.
        e.displacement(0, 4, false);
    }
}

void emit_mov_reg_reg(Emitter& e, x64::Reg dst, x64::Reg src) {
    if (!valid_size(dst.size) || dst.size != src.size) {
        e.fail("mov operands must have the same valid width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_mov_reg_reg(e, dst, src), "Xbyak could not encode mov reg, reg");
    const bool force = needs_rex8(dst) || needs_rex8(src);
    emit_reg_prefixes(e, dst.size, src.id >= 8, dst.id >= 8, force);
    e.byte(dst.size == 1 ? 0x88 : 0x89);
    e.modrm(3, src.low3(), dst.low3(), src.wildcard, dst.wildcard);
}

void emit_mov_reg_imm(Emitter& e, x64::Reg dst, std::int64_t imm) {
    if (!valid_size(dst.size)) {
        e.fail("invalid register width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_mov_reg_imm(e, dst, imm), "Xbyak could not encode mov reg, imm");

    if (dst.size == 8 && !fits_i32(imm)) {
        emit_reg_prefixes(e, 8, false, dst.id >= 8, false);
        e.byte(static_cast<std::uint8_t>(0xB8 + dst.low3()), dst.wildcard ? static_cast<std::uint8_t>(0xF8) : 0xFF);
        e.immediate(static_cast<std::uint64_t>(imm), 8, false);
        return;
    }

    if (dst.size == 8) {
        emit_reg_prefixes(e, 8, false, dst.id >= 8, false);
        e.byte(0xC7);
        e.modrm(3, 0, dst.low3(), false, dst.wildcard);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(imm)), 4, false);
        return;
    }

    if (dst.size == 4) {
        emit_reg_prefixes(e, 4, false, dst.id >= 8, false);
        e.byte(static_cast<std::uint8_t>(0xB8 + dst.low3()), dst.wildcard ? static_cast<std::uint8_t>(0xF8) : 0xFF);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(imm)), 4, false);
        return;
    }

    if (dst.size == 2) {
        emit_reg_prefixes(e, 2, false, dst.id >= 8, false);
        e.byte(static_cast<std::uint8_t>(0xB8 + dst.low3()), dst.wildcard ? static_cast<std::uint8_t>(0xF8) : 0xFF);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint16_t>(imm)), 2, false);
        return;
    }

    emit_reg_prefixes(e, 1, false, dst.id >= 8, needs_rex8(dst));
    e.byte(static_cast<std::uint8_t>(0xB0 + dst.low3()), dst.wildcard ? static_cast<std::uint8_t>(0xF8) : 0xFF);
    e.immediate(static_cast<std::uint64_t>(static_cast<std::uint8_t>(imm)), 1, false);
}

void emit_mov_reg_mem(Emitter& e, x64::Reg dst, const x64::Mem& src) {
    if (!valid_size(dst.size)) {
        e.fail("invalid destination register");
        return;
    }
    if (src.size != 0 && src.size != dst.size) {
        e.fail("memory operand width does not match destination register");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_mov_reg_mem(e, dst, src), "Xbyak could not encode mov reg, mem");
    emit_reg_prefixes(e, dst.size, dst.id >= 8, !src.wildcard_base && src.base.id >= 8, needs_rex8(dst));
    e.byte(dst.size == 1 ? 0x8A : 0x8B);
    emit_modrm_mem(e, dst, src);
}

void emit_mov_mem_reg(Emitter& e, const x64::Mem& dst, x64::Reg src) {
    const std::uint8_t size = dst.size != 0 ? dst.size : src.size;
    if (!valid_size(size) || size != src.size) {
        e.fail("memory operand width does not match source register");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_mov_mem_reg(e, dst, src), "Xbyak could not encode mov mem, reg");
    emit_reg_prefixes(e, size, src.id >= 8, !dst.wildcard_base && dst.base.id >= 8, needs_rex8(src));
    e.byte(size == 1 ? 0x88 : 0x89);
    emit_modrm_mem(e, src, dst);
}

void emit_mov_mem_imm(Emitter& e, const x64::Mem& dst, std::int32_t imm) {
    const std::uint8_t size = dst.size != 0 ? dst.size : 4;
    if (!valid_size(size)) {
        e.fail("invalid memory operand width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_mov_mem_imm(e, dst, imm, size), "Xbyak could not encode mov mem, imm");
    if (size == 8) {
        emit_reg_prefixes(e, 8, false, !dst.wildcard_base && dst.base.id >= 8, false);
        e.byte(0xC7);
        emit_modrm_mem(e, x64::Reg{0, 8, false}, dst);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(imm)), 4, false);
        return;
    }
    if (size == 2) {
        emit_reg_prefixes(e, 2, false, !dst.wildcard_base && dst.base.id >= 8, false);
        e.byte(0xC7);
        emit_modrm_mem(e, x64::Reg{0, 2, false}, dst);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint16_t>(imm)), 2, false);
        return;
    }
    if (size == 4) {
        emit_reg_prefixes(e, 4, false, !dst.wildcard_base && dst.base.id >= 8, false);
        e.byte(0xC7);
        emit_modrm_mem(e, x64::Reg{0, 4, false}, dst);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(imm)), 4, false);
        return;
    }
    emit_reg_prefixes(e, 1, false, !dst.wildcard_base && dst.base.id >= 8, false);
    e.byte(0xC6);
    emit_modrm_mem(e, x64::Reg{0, 1, false}, dst);
    e.immediate(static_cast<std::uint64_t>(static_cast<std::uint8_t>(imm)), 1, false);
}

void emit_lea(Emitter& e, x64::Reg dst, const x64::Mem& src) {
    if (!valid_size(dst.size)) {
        e.fail("invalid destination register");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_lea(e, dst, src), "Xbyak could not encode lea");
    emit_reg_prefixes(e, dst.size, dst.id >= 8, !src.wildcard_base && src.base.id >= 8, needs_rex8(dst));
    e.byte(0x8D);
    emit_modrm_mem(e, dst, src);
}

void emit_alu_reg_reg(Emitter& e, AluOp op, x64::Reg dst, x64::Reg src) {
    if (!valid_size(dst.size) || dst.size != src.size) {
        e.fail("ALU operands must have the same valid width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_alu_reg_reg(e, op, dst, src), "Xbyak could not encode ALU reg, reg");
    std::uint8_t opcode = 0;
    if (dst.size == 1) {
        switch (op) {
        case AluOp::add:
            opcode = 0x00;
            break;
        case AluOp::or_:
            opcode = 0x08;
            break;
        case AluOp::and_:
            opcode = 0x20;
            break;
        case AluOp::sub:
            opcode = 0x28;
            break;
        case AluOp::xor_:
            opcode = 0x30;
            break;
        case AluOp::cmp:
            opcode = 0x38;
            break;
        }
    } else {
        switch (op) {
        case AluOp::add:
            opcode = 0x01;
            break;
        case AluOp::or_:
            opcode = 0x09;
            break;
        case AluOp::and_:
            opcode = 0x21;
            break;
        case AluOp::sub:
            opcode = 0x29;
            break;
        case AluOp::xor_:
            opcode = 0x31;
            break;
        case AluOp::cmp:
            opcode = 0x39;
            break;
        }
    }
    emit_reg_prefixes(e, dst.size, src.id >= 8, dst.id >= 8, needs_rex8(dst) || needs_rex8(src));
    e.byte(opcode);
    e.modrm(3, src.low3(), dst.low3(), src.wildcard, dst.wildcard);
}

void emit_alu_reg_imm(Emitter& e, AluOp op, x64::Reg dst, std::int32_t imm) { emit_alu_imm(e, op, dst, imm); }

void emit_test_reg_reg(Emitter& e, x64::Reg dst, x64::Reg src) {
    if (!valid_size(dst.size) || dst.size != src.size) {
        e.fail("test operands must have the same valid width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_test_reg_reg(e, dst, src), "Xbyak could not encode test reg, reg");
    emit_reg_prefixes(e, dst.size, src.id >= 8, dst.id >= 8, needs_rex8(dst) || needs_rex8(src));
    e.byte(dst.size == 1 ? 0x84 : 0x85);
    e.modrm(3, src.low3(), dst.low3(), src.wildcard, dst.wildcard);
}

void emit_test_reg_imm(Emitter& e, x64::Reg dst, std::int32_t imm) {
    if (!valid_size(dst.size)) {
        e.fail("invalid register width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_test_reg_imm(e, dst, imm), "Xbyak could not encode test reg, imm");
    emit_reg_prefixes(e, dst.size, false, dst.id >= 8, needs_rex8(dst));
    e.byte(dst.size == 1 ? 0xF6 : 0xF7);
    e.modrm(3, 0, dst.low3(), false, dst.wildcard);
    const std::uint8_t imm_size = dst.size == 1 ? 1 : (dst.size == 2 ? 2 : 4);
    e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(imm)), imm_size, false);
}

void emit_inc_dec(Emitter& e, x64::Reg reg, bool increment) {
    if (!valid_size(reg.size)) {
        e.fail("invalid register width");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_inc_dec(e, reg, increment), "Xbyak could not encode inc/dec");
    emit_reg_prefixes(e, reg.size, false, reg.id >= 8, needs_rex8(reg));
    e.byte(reg.size == 1 ? 0xFE : 0xFF);
    e.modrm(3, increment ? 0 : 1, reg.low3(), false, reg.wildcard);
}

void emit_push_pop(Emitter& e, x64::Reg reg, bool push) {
    if (!reg.valid()) {
        e.fail("push/pop requires a valid register");
        return;
    }
    IPATCH_XBYAK_OR_FAIL(e, xbyak_push_pop(e, reg, push), "Xbyak could not encode push/pop");
    e.rex(false, false, false, reg.id >= 8, false);
    const std::uint8_t base = push ? 0x50 : 0x58;
    e.byte(static_cast<std::uint8_t>(base + reg.low3()), reg.wildcard ? static_cast<std::uint8_t>(0xF8) : 0xFF);
}

#undef IPATCH_XBYAK_OR_FAIL

void emit_jcc(Emitter& e, std::uint8_t condition, void* target) {
    condition &= 0x0F;
    if (e.pattern_mode() || target == nullptr) {
        if (!e.pattern_mode()) {
            e.fail("relative jump requires a target");
            return;
        }
        e.byte(static_cast<std::uint8_t>(0x70 | condition));
        e.wildcard(1);
        return;
    }
    const auto         next8       = static_cast<std::int64_t>(e.address() + 2);
    const auto         destination = reinterpret_cast<std::int64_t>(target);
    const std::int64_t rel8        = destination - next8;
    if (fits_i8(rel8)) {
        e.byte(static_cast<std::uint8_t>(0x70 | condition));
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint8_t>(rel8)), 1, false);
        return;
    }
    e.byte(0x0F);
    e.byte(static_cast<std::uint8_t>(0x80 | condition));
    const auto         next32 = static_cast<std::int64_t>(e.address() + 6);
    const std::int64_t rel32  = destination - next32;
    if (!fits_i32(rel32)) {
        e.fail("conditional jump target is out of rel32 range");
        return;
    }
    e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(rel32)), 4, false);
}

void emit_jmp(Emitter& e, void* target, bool force_short) {
    if (e.pattern_mode() || target == nullptr) {
        if (!e.pattern_mode()) {
            e.fail("jmp requires a target");
            return;
        }
        e.byte(0xEB);
        e.wildcard(1);
        return;
    }
    const auto         destination = reinterpret_cast<std::int64_t>(target);
    const auto         next8       = static_cast<std::int64_t>(e.address() + 2);
    const std::int64_t rel8        = destination - next8;
    if (force_short) {
        if (!fits_i8(rel8)) {
            e.fail("short jump target is out of rel8 range");
            return;
        }
        e.byte(0xEB);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint8_t>(rel8)), 1, false);
        return;
    }
    const auto         next32 = static_cast<std::int64_t>(e.address() + 5);
    const std::int64_t rel32  = destination - next32;
    if (fits_i32(rel32)) {
        e.byte(0xE9);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(rel32)), 4, false);
        return;
    }
    emit_jmp_abs(e, target);
}

void emit_jmp_abs(Emitter& e, void* target) {
    e.byte(0xFF);
    e.byte(0x25);
    e.immediate(0, 4, false);
    if (e.pattern_mode() || target == nullptr) {
        if (!e.pattern_mode()) {
            e.fail("absolute jump requires a target");
            return;
        }
        e.wildcard(8);
        return;
    }
    e.immediate(reinterpret_cast<std::uint64_t>(target), 8, false);
}

void emit_call(Emitter& e, void* target) {
    if (e.pattern_mode() || target == nullptr) {
        if (!e.pattern_mode()) {
            e.fail("call requires a target");
            return;
        }
        e.byte(0xE8);
        e.wildcard(4);
        return;
    }
    const auto         destination = reinterpret_cast<std::int64_t>(target);
    const auto         next        = static_cast<std::int64_t>(e.address() + 5);
    const std::int64_t rel32       = destination - next;
    if (fits_i32(rel32)) {
        e.byte(0xE8);
        e.immediate(static_cast<std::uint64_t>(static_cast<std::uint32_t>(rel32)), 4, false);
        return;
    }

    // call qword ptr [rip+2]; jmp +8; dq target
    e.byte(0xFF);
    e.byte(0x15);
    e.immediate(2, 4, false);
    e.byte(0xEB);
    e.immediate(8, 1, false);
    e.immediate(reinterpret_cast<std::uint64_t>(target), 8, false);
}

void emit_ret(Emitter& e) { e.byte(0xC3); }
void emit_int3(Emitter& e) { e.byte(0xCC); }
void emit_nop(Emitter& e) { e.byte(0x90); }

} // namespace ipatch::detail
