// SPDX-License-Identifier: MIT
#include "decoder.hpp"

#include <cstring>

namespace ipatch::detail {
namespace {

[[nodiscard]] std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

[[nodiscard]] bool has_modrm_1byte(std::uint8_t op) noexcept {
    switch (op) {
    case 0x62:
    case 0x63:
    case 0x69:
    case 0x6B:
        return true;
    default:
        break;
    }
    if (op <= 0x3B) {
        const std::uint8_t low  = op & 0x07;
        const std::uint8_t base = op & 0xFC;
        if (low <= 3
            && (base == 0x00 || base == 0x08 || base == 0x10 || base == 0x18 || base == 0x20 || base == 0x28
                || base == 0x30 || base == 0x38)) {
            return true;
        }
        return false;
    }
    if (op >= 0x80 && op <= 0x8F) return true;
    if (op == 0xC0 || op == 0xC1 || (op >= 0xC4 && op <= 0xC7)) return true;
    if (op >= 0xD0 && op <= 0xD3) return true;
    if (op >= 0xD8 && op <= 0xDF) return true;
    if (op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF) return true;
    return false;
}

[[nodiscard]] bool has_modrm_0f(std::uint8_t op) noexcept {
    if (op >= 0x80 && op <= 0x8F) return false; // jcc rel32
    if (op >= 0xC8 && op <= 0xCF) return false; // bswap
    switch (op) {
    case 0x05: // syscall
    case 0x06: // clts
    case 0x07: // sysret
    case 0x08: // invd
    case 0x09: // wbinvd
    case 0x0B: // ud2
    case 0x0E: // femms
    case 0x30: // wrmsr
    case 0x31: // rdtsc
    case 0x32: // rdmsr
    case 0x33: // rdpmc
    case 0x34: // sysenter
    case 0x35: // sysexit
    case 0x37: // getsec
    case 0x77: // emms / vzeroupper
    case 0xA0: // push fs
    case 0xA1: // pop fs
    case 0xA2: // cpuid
    case 0xA8: // push gs
    case 0xA9: // pop gs
    case 0xAA: // rsm
        return false;
    default:
        return true;
    }
}

[[nodiscard]] std::uint8_t imm_size_0f(std::uint8_t op) noexcept {
    if (op >= 0x80 && op <= 0x8F) return 4;
    if (op >= 0x70 && op <= 0x73) return 1;
    switch (op) {
    case 0x0F: // 3DNow suffix
    case 0xA4:
    case 0xAC:
    case 0xBA:
    case 0xC2:
    case 0xC4:
    case 0xC5:
    case 0xC6:
        return 1;
    default:
        break;
    }
    return 0;
}

[[nodiscard]] std::uint8_t imm_size_1byte(std::uint8_t op, bool opsize16, bool rexw, std::uint8_t modrm_reg) noexcept {
    const std::uint8_t imm16_or_32 = opsize16 ? 2 : 4;
    switch (op) {
    case 0x04:
    case 0x0C:
    case 0x14:
    case 0x1C:
    case 0x24:
    case 0x2C:
    case 0x34:
    case 0x3C:
    case 0x6A:
    case 0x80:
    case 0x83:
    case 0xA8:
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB4:
    case 0xB5:
    case 0xB6:
    case 0xB7:
    case 0xC0:
    case 0xC1:
    case 0xC6:
    case 0xCD:
    case 0xD4:
    case 0xD5:
    case 0xE4:
    case 0xE5:
    case 0xE6:
    case 0xE7:
        return 1;
    case 0x05:
    case 0x0D:
    case 0x15:
    case 0x1D:
    case 0x25:
    case 0x2D:
    case 0x35:
    case 0x3D:
    case 0x68:
    case 0x69:
    case 0x81:
    case 0xA9:
    case 0xC7:
        return imm16_or_32;
    case 0x6B:
        return 1;
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF:
        return rexw ? 8 : imm16_or_32;
    case 0xC2:
    case 0xCA:
        return 2;
    case 0xC8:
        return 3; // imm16 + imm8
    case 0xF6:
        return modrm_reg == 0 ? 1 : 0;
    case 0xF7:
        return modrm_reg == 0 ? imm16_or_32 : 0;
    case 0x9A:
    case 0xEA:
        return opsize16 ? 4 : 6; // far pointer (invalid in long mode, but length is known)
    case 0xA0:
    case 0xA1:
    case 0xA2:
    case 0xA3:
        return 4; // moffs size is address-size dependent; handled by caller
    default:
        return 0;
    }
}

void mark_rel(Insn& insn, RelKind kind, std::uint8_t offset, std::uint8_t size, std::uint8_t condition = 0) noexcept {
    insn.rel        = kind;
    insn.rel_offset = offset;
    insn.rel_size   = size;
    insn.condition  = condition;
    if (kind == RelKind::jmp8 || kind == RelKind::jmp32) insn.is_jmp = true;
    if (kind == RelKind::call32) insn.is_call = true;
}

} // namespace

std::int64_t Insn::relative_target(const std::uint8_t* code, std::uint64_t instruction_address) const noexcept {
    if (!code || rel_size == 0) return 0;
    std::int64_t displacement = 0;
    if (rel_size == 1) {
        displacement = static_cast<std::int8_t>(code[rel_offset]);
    } else if (rel_size == 4) {
        displacement = static_cast<std::int32_t>(read_u32(code + rel_offset));
    }
    return static_cast<std::int64_t>(instruction_address + length) + displacement;
}

std::int64_t Insn::rip_target(const std::uint8_t* code, std::uint64_t instruction_address) const noexcept {
    if (!code || !rip_relative || disp_size != 4) return 0;
    const auto displacement = static_cast<std::int32_t>(read_u32(code + disp_offset));
    return static_cast<std::int64_t>(instruction_address + length) + displacement;
}

bool decode_one(const std::uint8_t* code, std::size_t available, Insn& out) noexcept {
    out = Insn{};
    if (!code || available == 0) return false;

    std::size_t  pos         = 0;
    bool         opsize16    = false;
    bool         addrsize32  = false;
    bool         rex_present = false;
    std::uint8_t rex         = 0;

    for (;;) {
        if (pos >= available) return false;
        const std::uint8_t b = code[pos];
        if (b == 0x66) {
            opsize16    = true;
            rex         = 0;
            rex_present = false;
            ++pos;
            continue;
        }
        if (b == 0x67) {
            addrsize32  = true;
            rex         = 0;
            rex_present = false;
            ++pos;
            continue;
        }
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64
            || b == 0x65) {
            rex         = 0;
            rex_present = false;
            ++pos;
            continue;
        }
        if ((b & 0xF0) == 0x40) {
            rex         = b;
            rex_present = true;
            ++pos;
            continue;
        }
        break;
    }
    if (pos >= available) return false;

    const bool   rexw       = rex_present && (rex & 0x08) != 0;
    bool         vex        = false;
    std::uint8_t vex_map    = 0;
    std::uint8_t opcode     = 0;
    std::uint8_t opcode_map = 0;

    const std::uint8_t first = code[pos];
    if (first == 0xC5 || first == 0xC4 || first == 0x62) {
        // VEX/EVEX. These are only valid when no REX prefix was present.
        if (rex_present) return false;
        vex = true;
        if (first == 0xC5) {
            if (pos + 2 >= available) return false;
            vex_map  = 1;
            pos     += 2;
        } else if (first == 0xC4) {
            if (pos + 3 >= available) return false;
            vex_map  = static_cast<std::uint8_t>(code[pos + 1] & 0x1F);
            pos     += 3;
        } else {
            if (pos + 4 >= available) return false;
            vex_map  = static_cast<std::uint8_t>(code[pos + 1] & 0x03);
            pos     += 4;
        }
        if (vex_map < 1 || vex_map > 3) return false;
        opcode_map = vex_map;
        opcode     = code[pos++];
    } else {
        ++pos;
        if (first == 0x0F) {
            if (pos >= available) return false;
            opcode_map = 1;
            opcode     = code[pos++];
            if (opcode == 0x38 || opcode == 0x3A) {
                if (pos >= available) return false;
                opcode_map = opcode == 0x38 ? 2 : 3;
                opcode     = code[pos++];
            }
        } else {
            opcode_map = 0;
            opcode     = first;
        }
    }

    out.opcode_map = opcode_map;
    out.opcode     = opcode;

    bool has_modrm = false;
    if (vex) {
        has_modrm = !(opcode_map == 1 && opcode == 0x77);
    } else if (opcode_map == 0) {
        has_modrm = has_modrm_1byte(opcode);
    } else if (opcode_map == 1) {
        has_modrm = has_modrm_0f(opcode);
    } else {
        has_modrm = true;
    }

    out.has_modrm          = has_modrm;
    std::uint8_t modrm_reg = 0;
    if (has_modrm) {
        if (pos >= available) return false;
        out.modrm_offset         = static_cast<std::uint8_t>(pos);
        const std::uint8_t modrm = code[pos++];
        const std::uint8_t mod   = static_cast<std::uint8_t>(modrm >> 6);
        modrm_reg                = static_cast<std::uint8_t>((modrm >> 3) & 7);
        const std::uint8_t rm    = static_cast<std::uint8_t>(modrm & 7);
        if (mod != 3) {
            std::uint8_t disp = 0;
            bool         rip  = false;
            if (rm == 4) {
                if (pos >= available) return false;
                out.sib_offset          = static_cast<std::uint8_t>(pos);
                const std::uint8_t sib  = code[pos++];
                const std::uint8_t base = static_cast<std::uint8_t>(sib & 7);
                if (mod == 0 && base == 5) disp = 4;
            } else if (mod == 0 && rm == 5) {
                rip  = true;
                disp = 4;
            }
            if (mod == 1) disp = 1;
            else if (mod == 2) disp = 4;
            if (disp != 0) {
                if (pos + disp > available) return false;
                out.disp_offset   = static_cast<std::uint8_t>(pos);
                out.disp_size     = disp;
                pos              += disp;
                out.rip_relative  = rip;
            }
        }
    }

    std::uint8_t imm_size = 0;
    if (vex) {
        if (opcode_map == 3) {
            imm_size = 1;
        } else if (opcode_map == 1) {
            imm_size = imm_size_0f(opcode);
        }
    } else if (opcode_map == 0) {
        imm_size = imm_size_1byte(opcode, opsize16, rexw, modrm_reg);
        if ((opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA3)) {
            imm_size = addrsize32 ? 4 : 8;
        }
        if (opcode >= 0x70 && opcode <= 0x7F) imm_size = 1;
        if (opcode >= 0xE0 && opcode <= 0xE3) imm_size = 1;
        if (opcode == 0xEB) imm_size = 1;
        if (opcode == 0xE8 || opcode == 0xE9) imm_size = 4;
    } else if (opcode_map == 1) {
        imm_size = imm_size_0f(opcode);
    } else if (opcode_map == 3) {
        imm_size = 1;
    }

    if (imm_size != 0) {
        if (pos + imm_size > available) return false;
        out.imm_offset  = static_cast<std::uint8_t>(pos);
        out.imm_size    = imm_size;
        pos            += imm_size;
    }

    if (pos == 0 || pos > 15 || pos > available) return false;

    // Relative branches.
    if (opcode_map == 0) {
        if (opcode >= 0x70 && opcode <= 0x7F) {
            mark_rel(out, RelKind::jcc8, out.imm_offset, 1, static_cast<std::uint8_t>(opcode - 0x70));
        } else if (opcode >= 0xE0 && opcode <= 0xE3) {
            mark_rel(out, RelKind::loop8, out.imm_offset, 1, static_cast<std::uint8_t>(opcode - 0xE0));
        } else if (opcode == 0xEB) {
            mark_rel(out, RelKind::jmp8, out.imm_offset, 1);
        } else if (opcode == 0xE9) {
            mark_rel(out, RelKind::jmp32, out.imm_offset, 4);
        } else if (opcode == 0xE8) {
            mark_rel(out, RelKind::call32, out.imm_offset, 4);
        }
    } else if (opcode_map == 1 && opcode >= 0x80 && opcode <= 0x8F) {
        mark_rel(out, RelKind::jcc32, out.imm_offset, 4, static_cast<std::uint8_t>(opcode - 0x80));
    }

    out.is_ret     = (opcode_map == 0 && (opcode == 0xC3 || opcode == 0xC2 || opcode == 0xCB || opcode == 0xCA));
    out.is_int3    = (opcode_map == 0 && opcode == 0xCC);
    out.is_nop     = (opcode_map == 0 && opcode == 0x90) || (opcode_map == 1 && opcode == 0x1F);
    out.is_padding = out.is_int3 || out.is_nop || (opcode_map == 0 && opcode == 0x00 && !has_modrm);
    out.length     = static_cast<std::uint8_t>(pos);
    out.valid      = true;
    return true;
}

} // namespace ipatch::detail
