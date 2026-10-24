// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "ipatch/x64.hpp"
#include "win.hpp"

namespace ipatch::detail {

struct Encoded {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> mask;

    [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return bytes.size(); }
    void clear() noexcept {
        bytes.clear();
        mask.clear();
    }
    void push(std::uint8_t value, std::uint8_t m = 0xFF) {
        bytes.push_back(value);
        mask.push_back(m);
    }
};

class Emitter {
public:
    Emitter(Encoded& out, bool pattern_mode, std::uint64_t address)
        : out_(out), pattern_(pattern_mode), address_(address) {}

    [[nodiscard]] bool pattern_mode() const noexcept { return pattern_; }
    [[nodiscard]] std::uint64_t address() const noexcept { return address_; }
    [[nodiscard]] std::size_t position() const noexcept { return out_.size(); }
    [[nodiscard]] bool failed() const noexcept { return !error_.empty(); }
    [[nodiscard]] const std::string& error() const noexcept { return error_; }

    void fail(std::string message) {
        if (error_.empty()) error_ = std::move(message);
    }

    void byte(std::uint8_t value, std::uint8_t m = 0xFF) { out_.push(value, m); }

    void wildcard(std::size_t count = 1) {
        for (std::size_t i = 0; i < count; ++i) out_.push(0, 0);
    }

    void append(std::span<const std::uint8_t> bytes) {
        for (auto b : bytes) out_.push(b, 0xFF);
    }

    void rex(bool w, bool r, bool x, bool b, bool force = false) {
        const std::uint8_t value = static_cast<std::uint8_t>(
            0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0));
        if (value != 0x40 || force) byte(value);
    }

    void modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm, bool wildcard_reg,
               bool wildcard_rm) {
        std::uint8_t value = static_cast<std::uint8_t>((mod << 6) | ((reg & 7) << 3) | (rm & 7));
        std::uint8_t m = 0xFF;
        if (wildcard_reg) m &= static_cast<std::uint8_t>(~0x38);
        if (wildcard_rm) m &= static_cast<std::uint8_t>(~0x07);
        byte(value, m);
    }

    void sib(std::uint8_t scale, std::uint8_t index, std::uint8_t base, bool wildcard_index,
             bool wildcard_base) {
        std::uint8_t value = static_cast<std::uint8_t>(
            ((scale & 3) << 6) | ((index & 7) << 3) | (base & 7));
        std::uint8_t m = 0xFF;
        if (wildcard_index) m &= static_cast<std::uint8_t>(~0x38);
        if (wildcard_base) m &= static_cast<std::uint8_t>(~0x07);
        byte(value, m);
    }

    void displacement(std::int32_t value, std::uint8_t size, bool as_wildcard) {
        if (as_wildcard) {
            wildcard(size);
            return;
        }
        for (std::uint8_t i = 0; i < size; ++i) {
            byte(static_cast<std::uint8_t>((static_cast<std::uint64_t>(value) >> (i * 8)) & 0xFF));
        }
    }

    void immediate(std::uint64_t value, std::uint8_t size, bool as_wildcard) {
        if (as_wildcard) {
            wildcard(size);
            return;
        }
        for (std::uint8_t i = 0; i < size; ++i) {
            byte(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }

private:
    Encoded& out_;
    bool pattern_{false};
    std::uint64_t address_{0};
    std::string error_;
};

enum class AluOp : std::uint8_t {
    add = 0,
    or_ = 1,
    and_ = 4,
    sub = 5,
    xor_ = 6,
    cmp = 7,
};

void emit_prefixes(Emitter& e, std::uint8_t operand_size, bool rex_r = false,
                   bool rex_b = false, bool force_rex = false);
void emit_modrm_mem(Emitter& e, x64::Reg reg, const x64::Mem& mem);

void emit_mov_reg_reg(Emitter& e, x64::Reg dst, x64::Reg src);
void emit_mov_reg_imm(Emitter& e, x64::Reg dst, std::int64_t imm);
void emit_mov_reg_mem(Emitter& e, x64::Reg dst, const x64::Mem& src);
void emit_mov_mem_reg(Emitter& e, const x64::Mem& dst, x64::Reg src);
void emit_mov_mem_imm(Emitter& e, const x64::Mem& dst, std::int32_t imm);
void emit_lea(Emitter& e, x64::Reg dst, const x64::Mem& src);

void emit_alu_reg_reg(Emitter& e, AluOp op, x64::Reg dst, x64::Reg src);
void emit_alu_reg_imm(Emitter& e, AluOp op, x64::Reg dst, std::int32_t imm);
void emit_test_reg_reg(Emitter& e, x64::Reg dst, x64::Reg src);
void emit_test_reg_imm(Emitter& e, x64::Reg dst, std::int32_t imm);
void emit_inc_dec(Emitter& e, x64::Reg reg, bool increment);
void emit_push_pop(Emitter& e, x64::Reg reg, bool push);

void emit_jcc(Emitter& e, std::uint8_t condition, void* target);
void emit_jmp(Emitter& e, void* target, bool force_short = false);
void emit_jmp_abs(Emitter& e, void* target);
void emit_call(Emitter& e, void* target);
void emit_ret(Emitter& e);
void emit_int3(Emitter& e);
void emit_nop(Emitter& e);

} // namespace ipatch::detail
