// SPDX-License-Identifier: MIT
#include "relocation.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>

namespace ipatch::detail {
namespace {

[[nodiscard]] bool fits_i8(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int8_t>::min() && value <= std::numeric_limits<std::int8_t>::max();
}

[[nodiscard]] bool fits_i32(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int32_t>::min() && value <= std::numeric_limits<std::int32_t>::max();
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

[[nodiscard]] std::optional<std::size_t> instruction_index_for(
    const std::vector<RelocatedInsn>& insns,
    std::size_t                       old_offset
) {
    for (std::size_t i = 0; i < insns.size(); ++i) {
        if (insns[i].old_offset == old_offset) return i;
    }
    return std::nullopt;
}

[[nodiscard]] Result<std::vector<Insn>> decode_prologue(const std::uint8_t* source, std::size_t stolen_length) {
    std::vector<Insn> insns;
    std::size_t       offset = 0;
    while (offset < stolen_length) {
        Insn insn;
        if (!decode_one(source + offset, stolen_length - offset, insn)) {
            return fail(ErrorCode::decode_failed, "cannot decode instruction at +" + std::to_string(offset));
        }
        if (insn.length == 0 || offset + insn.length > stolen_length) {
            return fail(ErrorCode::decode_failed, "instruction crosses the stolen boundary");
        }
        insns.push_back(insn);
        offset += insn.length;
        if (insns.size() > 64) {
            return fail(ErrorCode::decode_failed, "stolen prologue has too many instructions");
        }
    }
    if (offset != stolen_length) {
        return fail(ErrorCode::decode_failed, "stolen length is not instruction aligned");
    }
    return insns;
}

[[nodiscard]] std::size_t encoding_size(const Insn& insn, std::int64_t target, std::int64_t new_ip) {
    switch (insn.rel) {
    case RelKind::jcc8: {
        const std::int64_t rel8 = target - (new_ip + 2);
        if (fits_i8(rel8)) return 2;
        const std::int64_t rel32 = target - (new_ip + 6);
        return fits_i32(rel32) ? 6 : 16;
    }
    case RelKind::jcc32: {
        const std::int64_t rel32 = target - (new_ip + 6);
        return fits_i32(rel32) ? 6 : 16;
    }
    case RelKind::jmp8: {
        const std::int64_t rel8 = target - (new_ip + 2);
        if (fits_i8(rel8)) return 2;
        const std::int64_t rel32 = target - (new_ip + 5);
        return fits_i32(rel32) ? 5 : 14;
    }
    case RelKind::jmp32: {
        const std::int64_t rel = target - (new_ip + 5);
        return fits_i32(rel) ? 5 : 14;
    }
    case RelKind::call32: {
        const std::int64_t rel = target - (new_ip + 5);
        return fits_i32(rel) ? 5 : 16;
    }
    case RelKind::loop8:
        return 2; // rejected later
    case RelKind::none:
        return insn.length;
    }
    return insn.length;
}

} // namespace

Result<Relocation> relocate(
    const std::uint8_t* source,
    std::size_t         stolen_length,
    std::uint8_t*       destination,
    std::size_t         capacity
) {
    if (!source || !destination || stolen_length == 0) {
        return fail(ErrorCode::invalid_argument, "relocate: null buffer or empty prologue");
    }

    auto decoded = decode_prologue(source, stolen_length);
    if (!decoded) return std::unexpected(decoded.error());
    const auto& insns = *decoded;

    std::vector<RelocatedInsn> layout;
    layout.reserve(insns.size());
    std::size_t offset = 0;
    for (const auto& insn : insns) {
        layout.push_back(RelocatedInsn{offset, insn.length, 0, insn.length});
        offset += insn.length;
    }

    const auto source_address      = reinterpret_cast<std::uint64_t>(source);
    const auto destination_address = reinterpret_cast<std::uint64_t>(destination);

    // Iterate until branch expansion stops changing instruction sizes. This is
    // a tiny fixed point: only short branches and far calls/jumps can grow.
    for (int iteration = 0; iteration < 8; ++iteration) {
        std::size_t new_offset = 0;
        for (auto& entry : layout) {
            entry.new_offset  = new_offset;
            new_offset       += entry.new_length;
        }

        bool changed = false;
        for (std::size_t i = 0; i < layout.size(); ++i) {
            const auto& insn = insns[i];
            if (insn.rel == RelKind::none) continue;
            if (insn.rel == RelKind::loop8) {
                return fail(ErrorCode::relocation_failed, "loop/jrcxz relocation is not supported");
            }

            const std::uint64_t old_ip = source_address + layout[i].old_offset;
            const auto target = static_cast<std::uint64_t>(insn.relative_target(source + layout[i].old_offset, old_ip));
            std::uint64_t relocated_target = target;
            if (target >= source_address && target < source_address + stolen_length) {
                const auto target_offset = static_cast<std::size_t>(target - source_address);
                const auto index         = instruction_index_for(layout, target_offset);
                if (!index) {
                    return fail(ErrorCode::relocation_failed, "branch target points into the middle of an instruction");
                }
                relocated_target = destination_address + layout[*index].new_offset;
            }

            const std::size_t needed = encoding_size(
                insn,
                static_cast<std::int64_t>(relocated_target),
                static_cast<std::int64_t>(destination_address + layout[i].new_offset)
            );
            if (needed != layout[i].new_length) {
                layout[i].new_length = needed;
                changed              = true;
            }
        }

        // RIP-relative operands never change size, but their displacement must
        // still fit in 32 bits from the new location.
        for (std::size_t i = 0; i < layout.size(); ++i) {
            const auto& insn = insns[i];
            if (!insn.rip_relative) continue;
            const std::uint64_t old_ip = source_address + layout[i].old_offset;
            const auto target = static_cast<std::uint64_t>(insn.rip_target(source + layout[i].old_offset, old_ip));
            const auto new_ip = destination_address + layout[i].new_offset;
            if (!fits_i32(
                    static_cast<std::int64_t>(target) - static_cast<std::int64_t>(new_ip + layout[i].new_length)
                )) {
                return fail(
                    ErrorCode::relocation_failed,
                    "RIP-relative displacement does not fit in 32 bits; "
                    "trampoline is too far from the target"
                );
            }
        }

        if (!changed) break;
        if (iteration == 7) {
            return fail(ErrorCode::relocation_failed, "branch layout did not converge");
        }
    }

    std::size_t total = 0;
    for (const auto& entry : layout) total += entry.new_length;
    total += 14; // worst-case absolute jump back
    if (total > capacity) {
        return fail(ErrorCode::allocation_failed, "trampoline buffer is too small");
    }

    Relocation result;
    result.stolen_length = stolen_length;
    result.instructions  = layout;
    result.code.reserve(total);

    for (std::size_t i = 0; i < layout.size(); ++i) {
        const auto&         insn   = insns[i];
        const auto&         entry  = layout[i];
        const std::uint64_t old_ip = source_address + entry.old_offset;
        const std::uint64_t new_ip = destination_address + entry.new_offset;

        if (insn.rel != RelKind::none) {
            const auto    target = static_cast<std::uint64_t>(insn.relative_target(source + entry.old_offset, old_ip));
            std::uint64_t relocated_target = target;
            if (target >= source_address && target < source_address + stolen_length) {
                const auto target_offset = static_cast<std::size_t>(target - source_address);
                const auto index         = instruction_index_for(layout, target_offset);
                if (!index) {
                    return fail(ErrorCode::relocation_failed, "branch target points into the middle of an instruction");
                }
                relocated_target = destination_address + layout[*index].new_offset;
            }

            switch (insn.rel) {
            case RelKind::jcc8:
            case RelKind::jcc32:
                if (entry.new_length == 2) {
                    const auto rel =
                        static_cast<std::int64_t>(relocated_target) - static_cast<std::int64_t>(new_ip + 2);
                    if (!fits_i8(rel)) {
                        return fail(ErrorCode::relocation_failed, "short jcc no longer fits");
                    }
                    result.code.push_back(static_cast<std::uint8_t>(0x70 | insn.condition));
                    result.code.push_back(static_cast<std::uint8_t>(rel));
                } else if (entry.new_length == 6) {
                    const auto rel =
                        static_cast<std::int64_t>(relocated_target) - static_cast<std::int64_t>(new_ip + 6);
                    if (!fits_i32(rel)) {
                        return fail(ErrorCode::relocation_failed, "jcc rel32 overflow");
                    }
                    result.code.push_back(0x0F);
                    result.code.push_back(static_cast<std::uint8_t>(0x80 | insn.condition));
                    put_u32(result.code, static_cast<std::uint32_t>(rel));
                } else {
                    // Invert the condition to skip an absolute jump:
                    //   jcc +14 ; FF 25 00 00 00 00 <abs64>
                    result.code.push_back(static_cast<std::uint8_t>(0x70 | (insn.condition ^ 1)));
                    result.code.push_back(0x0E);
                    result.code.push_back(0xFF);
                    result.code.push_back(0x25);
                    put_u32(result.code, 0);
                    put_u64(result.code, relocated_target);
                }
                break;
            case RelKind::jmp8:
                if (entry.new_length == 2) {
                    const auto rel =
                        static_cast<std::int64_t>(relocated_target) - static_cast<std::int64_t>(new_ip + 2);
                    if (!fits_i8(rel)) {
                        return fail(ErrorCode::relocation_failed, "short jmp no longer fits");
                    }
                    result.code.push_back(0xEB);
                    result.code.push_back(static_cast<std::uint8_t>(rel));
                } else {
                    const auto rel =
                        static_cast<std::int64_t>(relocated_target) - static_cast<std::int64_t>(new_ip + 5);
                    if (!fits_i32(rel)) {
                        return fail(ErrorCode::relocation_failed, "jmp rel32 overflow");
                    }
                    result.code.push_back(0xE9);
                    put_u32(result.code, static_cast<std::uint32_t>(rel));
                }
                break;
            case RelKind::jmp32:
                if (entry.new_length == 5) {
                    const auto rel =
                        static_cast<std::int64_t>(relocated_target) - static_cast<std::int64_t>(new_ip + 5);
                    if (!fits_i32(rel)) {
                        return fail(ErrorCode::relocation_failed, "jmp rel32 overflow");
                    }
                    result.code.push_back(0xE9);
                    put_u32(result.code, static_cast<std::uint32_t>(rel));
                } else {
                    result.code.push_back(0xFF);
                    result.code.push_back(0x25);
                    put_u32(result.code, 0);
                    put_u64(result.code, relocated_target);
                }
                break;
            case RelKind::call32:
                if (entry.new_length == 5) {
                    const auto rel =
                        static_cast<std::int64_t>(relocated_target) - static_cast<std::int64_t>(new_ip + 5);
                    if (!fits_i32(rel)) {
                        return fail(ErrorCode::relocation_failed, "call rel32 overflow");
                    }
                    result.code.push_back(0xE8);
                    put_u32(result.code, static_cast<std::uint32_t>(rel));
                } else {
                    result.code.push_back(0xFF);
                    result.code.push_back(0x15);
                    put_u32(result.code, 2);
                    result.code.push_back(0xEB);
                    result.code.push_back(8);
                    put_u64(result.code, relocated_target);
                }
                break;
            case RelKind::loop8:
            case RelKind::none:
                return fail(ErrorCode::relocation_failed, "unexpected branch kind");
            }
            continue;
        }

        const std::size_t start = result.code.size();
        result.code.insert(result.code.end(), source + entry.old_offset, source + entry.old_offset + entry.old_length);

        if (insn.rip_relative) {
            const auto target = insn.rip_target(source + entry.old_offset, old_ip);
            const auto rel    = target - static_cast<std::int64_t>(new_ip + entry.new_length);
            if (!fits_i32(rel)) {
                return fail(ErrorCode::relocation_failed, "RIP-relative displacement overflow");
            }
            const std::size_t disp_pos = start + insn.disp_offset;
            result.code[disp_pos + 0]  = static_cast<std::uint8_t>(static_cast<std::uint32_t>(rel) & 0xFF);
            result.code[disp_pos + 1]  = static_cast<std::uint8_t>((static_cast<std::uint32_t>(rel) >> 8) & 0xFF);
            result.code[disp_pos + 2]  = static_cast<std::uint8_t>((static_cast<std::uint32_t>(rel) >> 16) & 0xFF);
            result.code[disp_pos + 3]  = static_cast<std::uint8_t>((static_cast<std::uint32_t>(rel) >> 24) & 0xFF);
        }
    }

    result.jump_back_offset = result.code.size();
    const auto jump_back    = source_address + stolen_length;
    const auto jump_back_rel =
        static_cast<std::int64_t>(jump_back) - static_cast<std::int64_t>(destination_address + result.code.size() + 5);
    if (fits_i32(jump_back_rel)) {
        result.code.push_back(0xE9);
        put_u32(result.code, static_cast<std::uint32_t>(jump_back_rel));
    } else {
        result.code.push_back(0xFF);
        result.code.push_back(0x25);
        put_u32(result.code, 0);
        put_u64(result.code, jump_back);
    }

    return result;
}

} // namespace ipatch::detail
