// SPDX-License-Identifier: MIT
#include "ipatch/patch.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "address.hpp"
#include "decoder.hpp"
#include "emitter.hpp"
#include "memory.hpp"
#include "threads.hpp"

namespace ipatch {
namespace detail {

enum class PlanMode {
    pattern,
    absolute,
    resolved,
};

struct PlannedWrite {
    std::byte*                            address{nullptr};
    std::vector<std::byte>                bytes;
    std::optional<std::vector<std::byte>> expected;
};

struct PlannedCheck {
    std::byte*             address{nullptr};
    std::vector<std::byte> expected;
};

struct PlanState {
    PlanMode                  mode{PlanMode::absolute};
    Pattern                   pattern;
    ScanQuery                 query;
    std::byte*                base{nullptr};
    std::byte*                match{nullptr};
    std::byte*                cursor{nullptr};
    std::ptrdiff_t            pending_offset{0};
    std::vector<PlannedWrite> writes;
    std::vector<PlannedCheck> checks;
    // Relays are executable pages owned by the plan until it is applied. The
    // applied Patch then owns them for as long as the jump can be reached.
    std::vector<Allocation>               allocations;
    std::vector<std::shared_ptr<void>>    runtime_contexts;
    std::byte*                            entry_address{nullptr};
    std::size_t                           entry_size{0};
    std::optional<std::vector<std::byte>> pending_expected;
    bool                                  verify{true};
    bool                                  freeze_threads{false};
    bool                                  unique{false};
    bool                                  applied{false};
    Error                                 error{};
};

struct StoredWrite {
    std::byte*             address{nullptr};
    std::vector<std::byte> original;
    std::vector<std::byte> patched;
};

struct PatchState {
    bool                               active{false};
    bool                               permanent{false};
    bool                               freeze_threads{false};
    std::vector<StoredWrite>           writes;
    std::vector<Allocation>            allocations;
    std::vector<std::shared_ptr<void>> runtime_contexts;
    std::byte*                         entry_address{nullptr};
    std::size_t                        entry_size{0};
    std::vector<std::byte>             entry_original;
};

// A permanent patch deliberately outlives its C++ handle. Keep its state in
// an intentionally process-lifetime registry so executable relay pages are
// never released while the target still jumps to them. The registry itself is
// heap allocated and therefore is not destroyed during DLL shutdown.
void retain_permanent_patch(std::unique_ptr<PatchState> state) noexcept {
    try {
        static auto*     registry = new std::vector<std::unique_ptr<PatchState>>();
        static auto*     mutex    = new std::mutex();
        std::scoped_lock lock(*mutex);
        registry->push_back(std::move(state));
    } catch (...) {
        // A destructor must not throw. The patch state is intentionally leaked
        // if the process cannot grow the retention registry; this still keeps
        // relay allocations alive and preserves the permanent write.
        state.release();
    }
}

namespace {

void set_error(PlanState& state, ErrorCode code, std::string message) {
    if (state.error.ok()) state.error = Error{code, std::move(message)};
}

void set_error(PlanState& state, const Error& error) {
    if (state.error.ok()) state.error = error;
}

Status ensure_resolved(PlanState& state) {
    if (!state.error.ok()) return std::unexpected(state.error);
    if (state.mode == PlanMode::resolved) return success();

    if (state.mode == PlanMode::absolute) {
        if (!state.base) {
            set_error(state, ErrorCode::invalid_argument, "no patch address was provided");
            return std::unexpected(state.error);
        }
        auto cursor = offset_address(state.base, state.pending_offset);
        if (!cursor) {
            set_error(state, cursor.error());
            return std::unexpected(state.error);
        }
        state.cursor = *cursor;
        state.mode   = PlanMode::resolved;
        return success();
    }

    if (state.pattern.empty()) {
        set_error(state, ErrorCode::invalid_pattern, "search pattern is empty");
        return std::unexpected(state.error);
    }

    ScanQuery query = state.query;
    query.add(state.pattern);

    if (state.unique) {
        const auto unique = query.require_unique();
        if (!unique) {
            set_error(state, unique.error());
            return std::unexpected(state.error);
        }
        state.match = unique->address;
    } else {
        const auto first = query.first();
        if (!first) {
            set_error(state, first.error().ok() ? Error{ErrorCode::not_found, "pattern not found"} : first.error());
            return std::unexpected(state.error);
        }
        state.match = first.value();
    }
    state.base  = state.match;
    auto cursor = offset_address(state.base, state.pending_offset);
    if (!cursor) {
        set_error(state, cursor.error());
        return std::unexpected(state.error);
    }
    state.cursor = *cursor;
    state.mode   = PlanMode::resolved;
    return success();
}

void sync_offset(PlanState& state) {
    if (state.base && state.cursor) {
        state.pending_offset = state.cursor - state.base;
    }
}

std::vector<std::byte> to_bytes(std::span<const std::uint8_t> input) {
    std::vector<std::byte> bytes(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        bytes[i] = static_cast<std::byte>(input[i]);
    }
    return bytes;
}

std::optional<std::vector<std::byte>> take_pending_expected(PlanState& state) {
    auto expected = std::move(state.pending_expected);
    state.pending_expected.reset();
    return expected;
}

void add_write(
    PlanState&                            state,
    std::byte*                            address,
    std::vector<std::byte>                bytes,
    std::optional<std::vector<std::byte>> expected = std::nullopt,
    bool                                  entry    = true
) {
    if (bytes.empty()) return;
    if (entry && state.entry_address == nullptr) {
        state.entry_address = address;
        state.entry_size    = bytes.size();
    }
    state.writes.push_back(PlannedWrite{address, std::move(bytes), std::move(expected)});
}

template <typename Fn>
void emit(PlanState& state, Fn&& fn) {
    if (!state.error.ok()) return;

    if (state.mode == PlanMode::pattern) {
        detail::Encoded encoded;
        detail::Emitter emitter(encoded, true, 0);
        std::invoke(std::forward<Fn>(fn), emitter);
        if (emitter.failed()) {
            set_error(state, ErrorCode::invalid_argument, emitter.error());
            return;
        }
        for (std::size_t i = 0; i < encoded.size(); ++i) {
            state.pattern.add(encoded.bytes[i], encoded.mask[i]);
        }
        return;
    }

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;

    detail::Encoded encoded;
    detail::Emitter emitter(encoded, false, reinterpret_cast<std::uint64_t>(state.cursor));
    std::invoke(std::forward<Fn>(fn), emitter);
    if (emitter.failed()) {
        set_error(state, ErrorCode::invalid_argument, emitter.error());
        return;
    }
    if (encoded.empty()) return;

    const auto size = encoded.size();
    add_write(state, state.cursor, to_bytes(encoded.bytes));
    state.cursor += size;
    sync_offset(state);
}

// ---------------------------------------------------------------------------
// Automatic jump pads ("springboards")
// ---------------------------------------------------------------------------
//
// A raw five-byte E9 is only possible when the destination is within +/-2 GiB
// and the site has five readable bytes. When either condition fails we build a
// small stub:
//
//   site:  E9 rel32 -> relay           (site has 5 bytes, destination is far)
//   site:  EB rel8  -> code cave       (site has only 2 bytes)
//   relay: E9 rel32 / FF 25 + abs64    (far jump)
//   relay: E8 rel32 / FF 15 + abs64    (far call, then jump back)
//
// Relay pages are private executable allocations owned by the Patch. Code
// caves are existing runs of 0xCC/0x90/0x00 padding inside rel8 range.

constexpr std::size_t kRelayPageSize = 0x1000;

constexpr std::size_t align_up(std::size_t value, std::size_t alignment) noexcept {
    return (value + alignment - 1) / alignment * alignment;
}

[[nodiscard]] bool fits_i8(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int8_t>::min() && value <= std::numeric_limits<std::int8_t>::max();
}

[[nodiscard]] bool fits_i32(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int32_t>::min() && value <= std::numeric_limits<std::int32_t>::max();
}

void append_u32(std::vector<std::byte>& bytes, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFF));
    }
}

void append_u64(std::vector<std::byte>& bytes, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFF));
    }
}

void emit_stack_store(std::vector<std::byte>& code, std::size_t offset, unsigned reg) {
    code.push_back(static_cast<std::byte>(0x48 | (reg >= 8 ? 0x04 : 0x00)));
    code.push_back(std::byte{0x89});
    code.push_back(static_cast<std::byte>(0x84 | ((reg & 7) << 3)));
    code.push_back(std::byte{0x24});
    append_u32(code, static_cast<std::uint32_t>(offset));
}

void emit_stack_load(std::vector<std::byte>& code, unsigned reg, std::size_t offset) {
    code.push_back(static_cast<std::byte>(0x48 | (reg >= 8 ? 0x04 : 0x00)));
    code.push_back(std::byte{0x8B});
    code.push_back(static_cast<std::byte>(0x84 | ((reg & 7) << 3)));
    code.push_back(std::byte{0x24});
    append_u32(code, static_cast<std::uint32_t>(offset));
}

void emit_xmm_store(std::vector<std::byte>& code, unsigned xmm, std::size_t offset) {
    code.push_back(std::byte{0xF3});
    if (xmm >= 8) code.push_back(std::byte{0x44});
    code.push_back(std::byte{0x0F});
    code.push_back(std::byte{0x7F});
    code.push_back(static_cast<std::byte>(0x84 | ((xmm & 7) << 3)));
    code.push_back(std::byte{0x24});
    append_u32(code, static_cast<std::uint32_t>(offset));
}

void emit_xmm_load(std::vector<std::byte>& code, unsigned xmm, std::size_t offset) {
    code.push_back(std::byte{0xF3});
    if (xmm >= 8) code.push_back(std::byte{0x44});
    code.push_back(std::byte{0x0F});
    code.push_back(std::byte{0x6F});
    code.push_back(static_cast<std::byte>(0x84 | ((xmm & 7) << 3)));
    code.push_back(std::byte{0x24});
    append_u32(code, static_cast<std::uint32_t>(offset));
}

void emit_lea_rax_from_rsp(std::vector<std::byte>& code, std::size_t offset) {
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x8D}, std::byte{0x84}, std::byte{0x24}});
    append_u32(code, static_cast<std::uint32_t>(offset));
}

[[nodiscard]] Result<Allocation> make_runtime_thunk(void* site, RuntimeInvoker invoker, void* context) {
    if (!site || !invoker) {
        return fail(ErrorCode::invalid_argument, "runtime patch requires a site and callback");
    }

    auto allocation = allocate_near(site, kRelayPageSize);
    if (!allocation) return std::unexpected(allocation.error());

    constexpr std::size_t  kContextOffset = 0x20; // Windows x64 call shadow space.
    constexpr std::size_t  kFrameSize     = align_up(kContextOffset + sizeof(CpuContext), 16);
    std::vector<std::byte> code;
    code.reserve(1024);

    // Capture flags before SUB/AND modify them, and keep the original RAX
    // alongside them. RAX then anchors this small entry frame while RSP is
    // aligned dynamically: a patch point may be in a prologue or a body.
    // [rax] = saved RAX, [rax+8] = flags, [rax+16] = injected return address.
    code.insert(code.end(), {std::byte{0x9C}, std::byte{0x50}, std::byte{0x48}, std::byte{0x89}, std::byte{0xE0}});
    // Allocate shadow space plus CpuContext and meet the Windows x64 ABI
    // before calling C++. The captured target RSP remains independent.
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x81}, std::byte{0xEC}});
    append_u32(code, static_cast<std::uint32_t>(kFrameSize));
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x83}, std::byte{0xE4}, std::byte{0xF0}});

    // Keep the generated layout explicit and compiler independent.
    constexpr auto rax   = kContextOffset + offsetof(CpuContext, rax);
    constexpr auto rcx   = kContextOffset + offsetof(CpuContext, rcx);
    constexpr auto rdx   = kContextOffset + offsetof(CpuContext, rdx);
    constexpr auto rbx   = kContextOffset + offsetof(CpuContext, rbx);
    constexpr auto rbp   = kContextOffset + offsetof(CpuContext, rbp);
    constexpr auto rsi   = kContextOffset + offsetof(CpuContext, rsi);
    constexpr auto rdi   = kContextOffset + offsetof(CpuContext, rdi);
    constexpr auto r8    = kContextOffset + offsetof(CpuContext, r8);
    constexpr auto r9    = kContextOffset + offsetof(CpuContext, r9);
    constexpr auto r10   = kContextOffset + offsetof(CpuContext, r10);
    constexpr auto r11   = kContextOffset + offsetof(CpuContext, r11);
    constexpr auto r12   = kContextOffset + offsetof(CpuContext, r12);
    constexpr auto r13   = kContextOffset + offsetof(CpuContext, r13);
    constexpr auto r14   = kContextOffset + offsetof(CpuContext, r14);
    constexpr auto r15   = kContextOffset + offsetof(CpuContext, r15);
    constexpr auto rsp   = kContextOffset + offsetof(CpuContext, rsp);
    constexpr auto rip   = kContextOffset + offsetof(CpuContext, rip);
    constexpr auto flags = kContextOffset + offsetof(CpuContext, rflags);
    constexpr auto xmm   = kContextOffset + offsetof(CpuContext, xmm);

    emit_stack_store(code, rcx, 1);
    emit_stack_store(code, rdx, 2);
    emit_stack_store(code, rbx, 3);
    emit_stack_store(code, rbp, 5);
    emit_stack_store(code, rsi, 6);
    emit_stack_store(code, rdi, 7);
    emit_stack_store(code, r8, 8);
    emit_stack_store(code, r9, 9);
    emit_stack_store(code, r10, 10);
    emit_stack_store(code, r11, 11);
    emit_stack_store(code, r12, 12);
    emit_stack_store(code, r13, 13);
    emit_stack_store(code, r14, 14);
    emit_stack_store(code, r15, 15);

    // All other GPRs are saved, so R11 can transfer the entry frame into
    // CpuContext without changing the anchored address in RAX.
    code.insert(code.end(), {std::byte{0x4C}, std::byte{0x8B}, std::byte{0x18}}); // mov r11,[rax]
    emit_stack_store(code, rax, 11);
    code.insert(code.end(), {std::byte{0x4C}, std::byte{0x8B}, std::byte{0x58}, std::byte{0x08}});
    emit_stack_store(code, flags, 11);
    code.insert(code.end(), {std::byte{0x4C}, std::byte{0x8B}, std::byte{0x58}, std::byte{0x10}});
    emit_stack_store(code, rip, 11);
    code.insert(code.end(), {std::byte{0x4C}, std::byte{0x8D}, std::byte{0x58}, std::byte{0x18}});
    emit_stack_store(code, rsp, 11);

    for (unsigned i = 0; i < 16; ++i) {
        emit_xmm_store(code, i, xmm + i * 16);
    }

    emit_lea_rax_from_rsp(code, kContextOffset);
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x89}, std::byte{0xC2}});
    code.insert(code.end(), {std::byte{0x48}, std::byte{0xB9}});
    append_u64(code, reinterpret_cast<std::uint64_t>(context));
    code.insert(code.end(), {std::byte{0x48}, std::byte{0xB8}});
    append_u64(code, reinterpret_cast<std::uint64_t>(invoker));
    code.insert(code.end(), {std::byte{0xFF}, std::byte{0xD0}}); // call rax

    for (unsigned i = 0; i < 16; ++i) {
        emit_xmm_load(code, i, xmm + i * 16);
    }
    emit_stack_load(code, 1, rcx);
    emit_stack_load(code, 2, rdx);
    emit_stack_load(code, 3, rbx);
    emit_stack_load(code, 5, rbp);
    emit_stack_load(code, 6, rsi);
    emit_stack_load(code, 7, rdi);
    emit_stack_load(code, 8, r8);
    emit_stack_load(code, 9, r9);
    emit_stack_load(code, 10, r10);
    emit_stack_load(code, 12, r12);
    emit_stack_load(code, 13, r13);
    emit_stack_load(code, 14, r14);
    emit_stack_load(code, 15, r15);
    emit_stack_load(code, 0, flags);
    code.insert(code.end(), {std::byte{0x50}, std::byte{0x9D}}); // push rax; popfq

    // Build a return frame below the selected target RSP. RAX, R10 and R11
    // are restored from that frame after the current CpuContext is no longer
    // addressable; the flags are restored last so the LEA/RET preparation
    // cannot overwrite callback changes to RFLAGS.
    emit_stack_load(code, 11, rip);
    emit_stack_load(code, 0, rsp);
    code.insert(
        code.end(),
        {std::byte{0x4C}, std::byte{0x89}, std::byte{0x58}, std::byte{0xF8}}
    ); // mov [rax-8], r11 (RIP)
    emit_stack_load(code, 11, r11);
    code.insert(code.end(), {std::byte{0x4C}, std::byte{0x89}, std::byte{0x58}, std::byte{0xF0}}); // mov [rax-16], r11
    emit_stack_load(code, 11, rax);
    code.insert(
        code.end(),
        {std::byte{0x4C}, std::byte{0x89}, std::byte{0x58}, std::byte{0xE8}}
    ); // mov [rax-24], r11 (saved RAX)
    emit_stack_load(code, 10, flags);
    code.insert(
        code.end(),
        {std::byte{0x4C}, std::byte{0x89}, std::byte{0x50}, std::byte{0xD8}}
    ); // mov [rax-40], r10 (flags)
    emit_stack_load(code, 10, r10);
    code.insert(code.end(), {std::byte{0x4C}, std::byte{0x89}, std::byte{0x50}, std::byte{0xE0}}); // mov [rax-32], r10
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x83}, std::byte{0xE8}, std::byte{0x28}}); // sub rax, 40
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x89}, std::byte{0xC4}});                  // mov rsp, rax
    code.insert(
        code.end(),
        {std::byte{0x48}, std::byte{0x8B}, std::byte{0x44}, std::byte{0x24}, std::byte{0x10}}
    ); // mov rax, [rsp+16]
    code.insert(
        code.end(),
        {std::byte{0x4C}, std::byte{0x8B}, std::byte{0x5C}, std::byte{0x24}, std::byte{0x18}}
    );                                                                            // mov r11, [rsp+24]
    emit_stack_load(code, 10, 0);                                                 // mov r10, [rsp] (saved flags)
    code.insert(code.end(), {std::byte{0x41}, std::byte{0x52}, std::byte{0x9D}}); // push r10; popfq
    emit_stack_load(code, 10, 8); // restore the target's R10 after popfq
    code.insert(
        code.end(),
        {std::byte{0x48}, std::byte{0x8D}, std::byte{0x64}, std::byte{0x24}, std::byte{0x20}, std::byte{0xC3}}
    ); // lea rsp,[rsp+32]; ret

    if (code.size() > allocation->size()) {
        return fail(ErrorCode::allocation_failed, "runtime callback thunk does not fit");
    }
    std::memcpy(allocation->data(), code.data(), code.size());
    flush_instruction_cache(Range::from(allocation->data(), code.size()));
    return allocation;
}

[[nodiscard]] std::vector<std::byte> absolute_jump(void* target) {
    std::vector<std::byte> bytes;
    bytes.reserve(14);
    bytes.push_back(std::byte{0xFF});
    bytes.push_back(std::byte{0x25});
    append_u32(bytes, 0);
    append_u64(bytes, reinterpret_cast<std::uint64_t>(target));
    return bytes;
}

[[nodiscard]] std::vector<std::byte> relative_jump(void* from, void* to) {
    std::vector<std::byte> bytes;
    const auto             next     = reinterpret_cast<std::int64_t>(from) + 5;
    const auto             relative = reinterpret_cast<std::int64_t>(to) - next;
    if (!fits_i32(relative)) return bytes;
    bytes.push_back(std::byte{0xE9});
    append_u32(bytes, static_cast<std::uint32_t>(relative));
    return bytes;
}

// A jump that is as small as possible at `from`.
[[nodiscard]] std::vector<std::byte> jump_stub(void* from, void* target) {
    auto relative = relative_jump(from, target);
    if (!relative.empty()) return relative;
    return absolute_jump(target);
}

// Calls `target` and then resumes at `return_address`. The call itself may use
// an inline absolute pointer; the return path is a normal jump back.
[[nodiscard]] std::vector<std::byte> call_stub(void* from, void* target, void* return_address) {
    std::vector<std::byte> bytes;
    bytes.reserve(32);

    const auto  call_next     = reinterpret_cast<std::int64_t>(from) + 5;
    const auto  call_relative = reinterpret_cast<std::int64_t>(target) - call_next;
    std::size_t call_size     = 0;
    if (fits_i32(call_relative)) {
        bytes.push_back(std::byte{0xE8});
        append_u32(bytes, static_cast<std::uint32_t>(call_relative));
        call_size = 5;
    } else {
        // call qword ptr [rip+2]; jmp +8; dq target
        bytes.push_back(std::byte{0xFF});
        bytes.push_back(std::byte{0x15});
        append_u32(bytes, 2);
        bytes.push_back(std::byte{0xEB});
        bytes.push_back(std::byte{0x08});
        append_u64(bytes, reinterpret_cast<std::uint64_t>(target));
        call_size = 16;
    }

    auto*      resume = static_cast<std::byte*>(from) + call_size;
    const auto resume_relative =
        reinterpret_cast<std::int64_t>(return_address) - (reinterpret_cast<std::int64_t>(resume) + 5);
    if (fits_i32(resume_relative)) {
        bytes.push_back(std::byte{0xE9});
        append_u32(bytes, static_cast<std::uint32_t>(resume_relative));
    } else {
        const auto absolute = absolute_jump(return_address);
        bytes.insert(bytes.end(), absolute.begin(), absolute.end());
    }
    return bytes;
}

[[nodiscard]] bool padding_byte(std::byte value) noexcept {
    const auto byte = std::to_integer<std::uint8_t>(value);
    return byte == 0xCC || byte == 0x90 || byte == 0x00;
}

[[nodiscard]] bool overlaps_planned(const PlanState& state, std::byte* address, std::size_t size) noexcept {
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    const auto end   = begin + size;
    for (const auto& allocation : state.allocations) {
        const auto range = allocation.range();
        if (begin < reinterpret_cast<std::uintptr_t>(range.end)
            && reinterpret_cast<std::uintptr_t>(range.begin) < end) {
            return true;
        }
    }
    for (const auto& write : state.writes) {
        const auto write_begin = reinterpret_cast<std::uintptr_t>(write.address);
        const auto write_end   = write_begin + write.bytes.size();
        if (begin < write_end && write_begin < end) return true;
    }
    return false;
}

[[nodiscard]] std::byte* find_code_cave(const PlanState& state, std::byte* site, std::size_t needed) {
    if (needed == 0 || needed > 127) return nullptr;

    for (std::ptrdiff_t distance = 2; distance <= 126; ++distance) {
        for (int direction : {1, -1}) {
            auto* candidate = site + direction * distance;
            if (direction > 0 && candidate < site + 2) continue;
            if (direction < 0 && candidate + needed > site) continue;
            if (overlaps_planned(state, candidate, needed)) continue;
            if (!is_readable(candidate, needed)) continue;
            if (!is_executable(candidate) || !is_executable(candidate + needed - 1)) {
                continue;
            }
            auto bytes = read_memory(candidate, needed);
            if (!bytes) continue;
            if (std::all_of(bytes->begin(), bytes->end(), padding_byte)) {
                return candidate;
            }
        }
    }
    return nullptr;
}

void auto_jmp(PlanState& state, void* target) {
    if (!state.error.ok()) return;
    if (state.mode == PlanMode::pattern) {
        detail::emit(state, [target](detail::Emitter& emitter) { detail::emit_jmp(emitter, target); });
        return;
    }

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;
    if (!target) {
        set_error(state, ErrorCode::invalid_argument, "jmp requires a target");
        return;
    }

    auto*      site           = state.cursor;
    const auto site_address   = reinterpret_cast<std::int64_t>(site);
    const auto target_address = reinterpret_cast<std::int64_t>(target);
    const bool direct         = fits_i32(target_address - (site_address + 5));

    if (direct && is_readable(site, 5)) {
        auto bytes = relative_jump(site, target);
        add_write(state, site, std::move(bytes));
        state.cursor += 5;
        sync_offset(state);
        return;
    }

    if (!direct && is_readable(site, 5)) {
        // The relay is written before the entry jump. The entry still points
        // at the original code, so threads cannot enter the relay until the
        // transaction below commits.
        auto allocation = allocate_near(site, kRelayPageSize);
        if (!allocation) {
            set_error(state, allocation.error());
            return;
        }
        auto*      relay    = static_cast<std::byte*>(allocation->data());
        const auto distance = reinterpret_cast<std::int64_t>(relay) - (reinterpret_cast<std::int64_t>(site) + 5);
        if (!fits_i32(distance)) {
            set_error(
                state,
                ErrorCode::out_of_range,
                "could not allocate a relay within rel32 range of the patch site"
            );
            return;
        }
        auto       relay_stub = jump_stub(relay, target);
        const auto written    = write_memory(relay, relay_stub);
        if (!written) {
            set_error(state, written.error());
            return;
        }
        state.allocations.push_back(std::move(*allocation));
        auto rel = relative_jump(site, relay);
        add_write(state, site, std::move(rel));
        state.freeze_threads  = true;
        state.cursor         += 5;
        sync_offset(state);
        return;
    }

    // Only two bytes are available at the site. Find nearby padding and use a
    // short jump to a complete stub. Both writes are applied in one frozen
    // transaction so no thread can observe the intermediate state.
    if (!is_readable(site, 2)) {
        set_error(state, ErrorCode::insufficient_space, "patch site has fewer than two writable bytes");
        return;
    }

    auto* cave = find_code_cave(state, site, 5);
    if (cave) {
        const auto cave_address = reinterpret_cast<std::int64_t>(cave);
        if (!fits_i32(target_address - (cave_address + 5))) {
            cave = find_code_cave(state, site, 14);
        }
    }
    if (!cave) cave = find_code_cave(state, site, 14);
    if (!cave) {
        set_error(state, ErrorCode::insufficient_space, "no nearby code cave with enough padding was found");
        return;
    }

    const auto relative = reinterpret_cast<std::int64_t>(cave) - (site_address + 2);
    if (!fits_i8(relative)) {
        set_error(state, ErrorCode::insufficient_space, "code cave is outside short-jump range");
        return;
    }

    auto cave_stub = jump_stub(cave, target);
    add_write(state, cave, std::move(cave_stub), std::nullopt, false);
    std::vector<std::byte> springboard;
    springboard.push_back(std::byte{0xEB});
    springboard.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(relative)));
    add_write(state, site, std::move(springboard));
    state.freeze_threads  = true;
    state.cursor         += 2;
    sync_offset(state);
}

void auto_jmp_abs(PlanState& state, void* target) {
    if (!state.error.ok()) return;
    if (state.mode == PlanMode::pattern) {
        detail::emit(state, [target](detail::Emitter& emitter) { detail::emit_jmp_abs(emitter, target); });
        return;
    }

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;
    if (!target) {
        set_error(state, ErrorCode::invalid_argument, "absolute jump requires a target");
        return;
    }

    auto* site = state.cursor;
    if (is_readable(site, 14)) {
        add_write(state, site, absolute_jump(target));
        state.cursor += 14;
        sync_offset(state);
        return;
    }

    if (is_readable(site, 5)) {
        auto allocation = allocate_near(site, kRelayPageSize);
        if (!allocation) {
            set_error(state, allocation.error());
            return;
        }
        auto*      relay    = static_cast<std::byte*>(allocation->data());
        const auto distance = reinterpret_cast<std::int64_t>(relay) - (reinterpret_cast<std::int64_t>(site) + 5);
        if (!fits_i32(distance)) {
            set_error(
                state,
                ErrorCode::out_of_range,
                "could not allocate a relay within rel32 range of the patch site"
            );
            return;
        }
        auto       stub    = jump_stub(relay, target);
        const auto written = write_memory(relay, stub);
        if (!written) {
            set_error(state, written.error());
            return;
        }
        state.allocations.push_back(std::move(*allocation));
        add_write(state, site, relative_jump(site, relay));
        state.freeze_threads  = true;
        state.cursor         += 5;
        sync_offset(state);
        return;
    }

    if (!is_readable(site, 2)) {
        set_error(state, ErrorCode::insufficient_space, "patch site has fewer than two writable bytes");
        return;
    }

    auto* cave = find_code_cave(state, site, 14);
    if (!cave) {
        set_error(state, ErrorCode::insufficient_space, "no nearby code cave with enough padding was found");
        return;
    }
    const auto relative = reinterpret_cast<std::int64_t>(cave) - (reinterpret_cast<std::int64_t>(site) + 2);
    if (!fits_i8(relative)) {
        set_error(state, ErrorCode::insufficient_space, "code cave is outside short-jump range");
        return;
    }

    add_write(state, cave, absolute_jump(target), std::nullopt, false);
    std::vector<std::byte> springboard;
    springboard.push_back(std::byte{0xEB});
    springboard.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(relative)));
    add_write(state, site, std::move(springboard));
    state.freeze_threads  = true;
    state.cursor         += 2;
    sync_offset(state);
}

void auto_call(PlanState& state, void* target) {
    if (!state.error.ok()) return;
    if (state.mode == PlanMode::pattern) {
        detail::emit(state, [target](detail::Emitter& emitter) { detail::emit_call(emitter, target); });
        return;
    }

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;
    if (!target) {
        set_error(state, ErrorCode::invalid_argument, "call requires a target");
        return;
    }

    auto*      site           = state.cursor;
    const auto site_address   = reinterpret_cast<std::int64_t>(site);
    const auto target_address = reinterpret_cast<std::int64_t>(target);
    const bool direct         = fits_i32(target_address - (site_address + 5));

    if (direct && is_readable(site, 5)) {
        std::vector<std::byte> bytes;
        bytes.push_back(std::byte{0xE8});
        append_u32(bytes, static_cast<std::uint32_t>(target_address - (site_address + 5)));
        add_write(state, site, std::move(bytes));
        state.cursor += 5;
        sync_offset(state);
        return;
    }

    if (is_readable(site, 5)) {
        auto allocation = allocate_near(site, kRelayPageSize);
        if (!allocation) {
            set_error(state, allocation.error());
            return;
        }
        auto*      relay    = static_cast<std::byte*>(allocation->data());
        const auto distance = reinterpret_cast<std::int64_t>(relay) - (reinterpret_cast<std::int64_t>(site) + 5);
        if (!fits_i32(distance)) {
            set_error(
                state,
                ErrorCode::out_of_range,
                "could not allocate a relay within rel32 range of the patch site"
            );
            return;
        }
        auto       stub    = call_stub(relay, target, site + 5);
        const auto written = write_memory(relay, stub);
        if (!written) {
            set_error(state, written.error());
            return;
        }
        state.allocations.push_back(std::move(*allocation));
        state.freeze_threads = true;
        std::vector<std::byte> bytes;
        bytes.push_back(std::byte{0xE8});
        append_u32(bytes, static_cast<std::uint32_t>(reinterpret_cast<std::int64_t>(relay) - (site_address + 5)));
        add_write(state, site, std::move(bytes));
        state.cursor += 5;
        sync_offset(state);
        return;
    }

    if (!is_readable(site, 2)) {
        set_error(state, ErrorCode::insufficient_space, "patch site has fewer than two writable bytes");
        return;
    }

    // A 10-byte stub is enough when the callee is within rel32 from the cave;
    // otherwise use the 21-byte absolute-call form.
    auto* cave = find_code_cave(state, site, 10);
    if (cave) {
        const auto cave_address = reinterpret_cast<std::int64_t>(cave);
        if (!fits_i32(target_address - (cave_address + 5))) {
            cave = find_code_cave(state, site, 21);
        }
    }
    if (!cave) cave = find_code_cave(state, site, 21);
    if (!cave) {
        set_error(state, ErrorCode::insufficient_space, "no nearby code cave with enough padding was found");
        return;
    }

    const auto relative = reinterpret_cast<std::int64_t>(cave) - (site_address + 2);
    if (!fits_i8(relative)) {
        set_error(state, ErrorCode::insufficient_space, "code cave is outside short-jump range");
        return;
    }

    // The original call is five bytes long. The two-byte short jump at the
    // site skips the rest of it, so the stub must resume at site + 5.
    add_write(state, cave, call_stub(cave, target, site + 5), std::nullopt, false);
    std::vector<std::byte> springboard;
    springboard.push_back(std::byte{0xEB});
    springboard.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(relative)));
    add_write(state, site, std::move(springboard));
    state.freeze_threads  = true;
    state.cursor         += 5;
    sync_offset(state);
}

void auto_write_springboard(PlanState& state, std::size_t original_length, std::span<const std::byte> bytes) {
    if (!state.error.ok()) return;

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;
    if (original_length == 0) {
        set_error(state, ErrorCode::invalid_argument, "write_springboard requires a non-zero original length");
        return;
    }

    auto*      site       = state.cursor;
    const auto site_value = reinterpret_cast<std::uintptr_t>(site);
    if (original_length > std::numeric_limits<std::uintptr_t>::max() - site_value) {
        set_error(state, ErrorCode::out_of_range, "original length overflows the patch address");
        return;
    }
    auto* resume = reinterpret_cast<std::byte*>(site_value + original_length);

    auto expected = take_pending_expected(state);
    if (expected && expected->size() != original_length) {
        set_error(state, ErrorCode::invalid_argument, "expect() size does not match the springboard original length");
        return;
    }

    // The replacement fits in the original byte range: write it directly and
    // NOP-pad the remainder so a partial original instruction is never left.
    if (bytes.size() <= original_length) {
        std::vector<std::byte> replacement(bytes.begin(), bytes.end());
        replacement.resize(original_length, std::byte{0x90});
        add_write(state, site, std::move(replacement), std::move(expected));
        state.cursor = resume;
        sync_offset(state);
        return;
    }

    if (expected) {
        state.checks.push_back(PlannedCheck{site, std::move(*expected)});
    }

    // An overlong replacement needs an entry jump. A minimum of two bytes is
    // required for EB rel8; a one-byte site cannot be safely redirected.
    if (original_length < 2) {
        set_error(state, ErrorCode::insufficient_space, "a springboard requires at least two original bytes");
        return;
    }

    const auto make_springboard = [&](std::byte* from) {
        std::vector<std::byte> stub(bytes.begin(), bytes.end());
        auto                   back = jump_stub(from, resume);
        if (back.empty()) return stub;
        stub.insert(stub.end(), back.begin(), back.end());
        return stub;
    };

    // Preferred path: five-byte entry to a relay page within rel32 range.
    if (original_length >= 5 && is_readable(site, 5)) {
        if (bytes.size() <= std::numeric_limits<std::size_t>::max() - 14) {
            std::size_t allocation_size = bytes.size() + 14;
            if (allocation_size < kRelayPageSize) allocation_size = kRelayPageSize;

            auto allocation = allocate_near(site, allocation_size);
            if (allocation) {
                auto*      relay = static_cast<std::byte*>(allocation->data());
                const auto distance =
                    reinterpret_cast<std::int64_t>(relay) - (reinterpret_cast<std::int64_t>(site) + 5);
                if (!fits_i32(distance)) {
                    set_error(
                        state,
                        ErrorCode::out_of_range,
                        "could not allocate a springboard relay within rel32 range"
                    );
                    return;
                }

                auto stub    = make_springboard(relay + bytes.size());
                auto written = write_memory(relay, stub);
                if (!written) {
                    set_error(state, written.error());
                    return;
                }
                state.allocations.push_back(std::move(*allocation));

                auto entry = relative_jump(site, relay);
                if (entry.empty()) {
                    set_error(state, ErrorCode::out_of_range, "springboard relay is outside rel32 range");
                    return;
                }
                add_write(state, site, std::move(entry));
                state.freeze_threads = true;
                state.cursor         = resume;
                sync_offset(state);
                return;
            }
        }
    }

    // Short-entry path: EB rel8 to a nearby padding cave. This is also the
    // fallback when a relay page cannot be allocated.
    if (!is_readable(site, 2)) {
        set_error(state, ErrorCode::insufficient_space, "springboard site has fewer than two readable bytes");
        return;
    }
    if (bytes.size() > std::numeric_limits<std::size_t>::max() - 5) {
        set_error(state, ErrorCode::out_of_range, "springboard stub is too large");
        return;
    }

    auto* cave = find_code_cave(state, site, bytes.size() + 5);
    if (!cave) {
        set_error(state, ErrorCode::insufficient_space, "no nearby code cave with enough padding for the springboard");
        return;
    }

    const auto relative = reinterpret_cast<std::int64_t>(cave) - (reinterpret_cast<std::int64_t>(site) + 2);
    if (!fits_i8(relative)) {
        set_error(state, ErrorCode::insufficient_space, "springboard cave is outside short-jump range");
        return;
    }

    std::vector<std::byte> stub(bytes.begin(), bytes.end());
    auto                   back = relative_jump(cave + bytes.size(), resume);
    if (back.empty()) {
        set_error(state, ErrorCode::out_of_range, "springboard cave cannot reach the resume address");
        return;
    }
    stub.insert(stub.end(), back.begin(), back.end());

    const auto cave_begin = reinterpret_cast<std::uintptr_t>(cave);
    const auto site_begin = reinterpret_cast<std::uintptr_t>(site);
    if (cave_begin < site_begin + 2 && site_begin < cave_begin + stub.size()) {
        set_error(state, ErrorCode::insufficient_space, "springboard cave overlaps the patch site");
        return;
    }

    add_write(state, cave, std::move(stub), std::nullopt, false);
    std::vector<std::byte> entry;
    entry.push_back(std::byte{0xEB});
    entry.push_back(static_cast<std::byte>(static_cast<std::uint8_t>(relative)));
    add_write(state, site, std::move(entry));
    state.freeze_threads = true;
    state.cursor         = resume;
    sync_offset(state);
}

void auto_write_springboard(PlanState& state, std::span<const std::byte> bytes) {
    if (!state.error.ok()) return;

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;

    auto* site   = state.cursor;
    auto  region = committed_region(site);
    if (!region) {
        set_error(state, region.error());
        return;
    }

    const std::size_t available = std::min<std::size_t>(15, region->size());
    auto              code      = read_memory(site, available);
    if (!code) {
        set_error(state, code.error());
        return;
    }

    Insn instruction;
    if (!decode_one(reinterpret_cast<const std::uint8_t*>(code->data()), code->size(), instruction)
        || instruction.length == 0) {
        set_error(state, ErrorCode::decode_failed, "cannot decode the original instruction for the springboard");
        return;
    }

    auto_write_springboard(state, instruction.length, bytes);
}

// Emits a conditional null guard that preserves one original instruction:
//
//   test reg, reg
//   jz   abs_jump
//   <original instruction>
//   jmp  short over_abs_jump
// abs_jump:
//   FF 25 00 00 00 00 <target abs64>
// over_abs_jump:
//   <iPatch-generated jump back to site + instruction.length>
//
// The local branches are fixed-size, so no relay address is needed while the
// stub is being built. `auto_write_springboard` appends the jump back.
void auto_guard_null(PlanState& state, x64::Reg reg, void* if_null) {
    if (!state.error.ok()) return;

    if (!reg.valid() || reg.wildcard || reg.size != 8 || reg.id > 15) {
        set_error(state, ErrorCode::invalid_argument, "guard_null requires a non-wildcard 64-bit register");
        return;
    }
    if (!if_null) {
        set_error(state, ErrorCode::invalid_argument, "guard_null requires a null-branch target");
        return;
    }

    const auto resolved = ensure_resolved(state);
    if (!resolved) return;

    auto* site   = state.cursor;
    auto  region = committed_region(site);
    if (!region) {
        set_error(state, region.error());
        return;
    }

    const std::size_t available = std::min<std::size_t>(15, region->size());
    auto              code      = read_memory(site, available);
    if (!code) {
        set_error(state, code.error());
        return;
    }

    Insn instruction;
    if (!decode_one(reinterpret_cast<const std::uint8_t*>(code->data()), code->size(), instruction)
        || instruction.length == 0) {
        set_error(state, ErrorCode::decode_failed, "cannot decode the instruction guarded by guard_null");
        return;
    }
    if (instruction.rip_relative || instruction.is_branch() || instruction.is_call || instruction.is_jmp
        || instruction.is_ret || instruction.is_int3) {
        set_error(
            state,
            ErrorCode::unsupported_instruction,
            "guard_null cannot preserve a RIP-relative or control-flow instruction"
        );
        return;
    }

    // The local branches are encoded with the same instruction emitter as the
    // public fluent API. Each Emitter is positioned at the current offset so
    // the relative displacements match the final stub layout.
    Encoded encoded;
    Emitter test_emitter(encoded, false, 0);
    emit_test_reg_reg(test_emitter, reg, reg);
    if (test_emitter.failed()) {
        set_error(state, ErrorCode::invalid_argument, test_emitter.error());
        return;
    }
    const auto test_size = encoded.size();
    if (test_size == 0) {
        set_error(state, ErrorCode::invalid_argument, "cannot encode the guard_null test instruction");
        return;
    }

    // test + jz rel8 + original + jmp short + FF 25 + abs64
    const auto absolute_offset = test_size + 2 + instruction.length + 2;
    Emitter    branch_emitter(encoded, false, test_size);
    emit_jcc(branch_emitter, 0x4, reinterpret_cast<void*>(absolute_offset));
    if (branch_emitter.failed() || encoded.size() != test_size + 2) {
        set_error(
            state,
            ErrorCode::invalid_argument,
            branch_emitter.failed() ? branch_emitter.error() : "guard_null jz is not a short branch"
        );
        return;
    }

    for (std::size_t i = 0; i < instruction.length; ++i) {
        encoded.push(static_cast<std::uint8_t>(code->at(i)));
    }

    if (encoded.size() != absolute_offset - 2) {
        set_error(state, ErrorCode::internal, "guard_null stub layout mismatch");
        return;
    }
    Emitter skip_emitter(encoded, false, absolute_offset - 2);
    emit_jmp(skip_emitter, reinterpret_cast<void*>(absolute_offset + 14), true);
    if (skip_emitter.failed() || encoded.size() != absolute_offset) {
        set_error(
            state,
            ErrorCode::invalid_argument,
            skip_emitter.failed() ? skip_emitter.error() : "guard_null skip jump is not a short branch"
        );
        return;
    }

    Emitter absolute_emitter(encoded, false, absolute_offset);
    emit_jmp_abs(absolute_emitter, if_null);
    if (absolute_emitter.failed() || encoded.size() != absolute_offset + 14) {
        set_error(
            state,
            ErrorCode::invalid_argument,
            absolute_emitter.failed() ? absolute_emitter.error() : "guard_null absolute jump layout mismatch"
        );
        return;
    }

    auto stub = to_bytes(std::span<const std::uint8_t>(encoded.bytes));
    auto_write_springboard(state, instruction.length, stub);
}

} // namespace
} // namespace detail

// ---------------------------------------------------------------------------
// Patch
// ---------------------------------------------------------------------------

Patch::Patch() = default;
Patch::Patch(std::unique_ptr<detail::PatchState> state) : state_(std::move(state)) {}

Patch::~Patch() {
    if (state_ && state_->active) {
        if (state_->permanent) {
            detail::retain_permanent_patch(std::move(state_));
            return;
        }
        // If restoration is not safe (e.g. a thread is still in the patched
        // range), leak the state and its relay pages rather than freeing a
        // page that the patch site may still jump to.
        if (!restore()) {
            state_.release();
        }
    }
}

Patch::Patch(Patch&& other) noexcept : state_(std::move(other.state_)) {}

Patch& Patch::operator=(Patch&& other) noexcept {
    if (this != &other) {
        if (state_ && state_->active) {
            if (state_->permanent) {
                detail::retain_permanent_patch(std::move(state_));
            } else if (!restore()) {
                state_.release();
            }
        }
        state_ = std::move(other.state_);
    }
    return *this;
}

Patcher Patch::at(void* address) {
    Patcher patcher;
    patcher.state_->mode           = detail::PlanMode::absolute;
    patcher.state_->base           = static_cast<std::byte*>(address);
    patcher.state_->cursor         = static_cast<std::byte*>(address);
    patcher.state_->pending_offset = 0;
    if (!address) {
        detail::set_error(*patcher.state_, ErrorCode::invalid_argument, "patch address is null");
    }
    return patcher;
}

Patcher Patch::at(Module module, std::uintptr_t rva) { return Patch::at(module.at(rva)); }

Patcher Patch::at(const MatchResult& address) {
    if (address) return Patch::at(address.address());
    Patcher patcher;
    detail::set_error(*patcher.state_, address.error());
    return patcher;
}

Patcher Patch::at(const Result<std::byte*>& address) { return Patch::at(MatchResult(address)); }

Patcher Patch::search(std::string_view signature) {
    Patcher patcher;
    patcher.state_->mode = detail::PlanMode::pattern;
    auto parsed          = Pattern::parse(signature);
    if (!parsed) {
        detail::set_error(*patcher.state_, parsed.error());
    } else {
        patcher.state_->pattern = std::move(*parsed);
    }
    return patcher;
}

Patcher Patch::search(Pattern pattern) {
    Patcher patcher;
    patcher.state_->mode = detail::PlanMode::pattern;
    if (!pattern.error().ok()) detail::set_error(*patcher.state_, pattern.error());
    patcher.state_->pattern = std::move(pattern);
    return patcher;
}

Patcher Patch::search() {
    Patcher patcher;
    patcher.state_->mode = detail::PlanMode::pattern;
    return patcher;
}

Patcher Patch::search_string(std::string_view text, bool null_terminated) {
    auto pattern = Pattern::from_string(text, null_terminated);
    auto patcher = Patch::search(pattern ? std::move(*pattern) : Pattern{});
    if (!pattern) detail::set_error(*patcher.state_, pattern.error());
    patcher.state_->query.executable_only(false);
    return patcher;
}

Patcher Patch::search_string(std::u16string_view text, bool null_terminated) {
    auto pattern = Pattern::from_string(text, null_terminated);
    auto patcher = Patch::search(pattern ? std::move(*pattern) : Pattern{});
    if (!pattern) detail::set_error(*patcher.state_, pattern.error());
    patcher.state_->query.executable_only(false);
    return patcher;
}

Status Patch::restore() {
    if (!state_ || !state_->active) return success();

    std::vector<Range> ranges;
    ranges.reserve(state_->writes.size());
    for (const auto& write : state_->writes) {
        ranges.push_back(Range::from(write.address, write.original.size()));
    }

    // Relay pages are not restored byte-for-byte, but a thread can still be
    // executing inside one when the entry jump is removed. Include them in the
    // RIP check before the allocation is released.
    std::vector<Range> rip_ranges = ranges;
    for (const auto& allocation : state_->allocations) {
        const auto range = allocation.range();
        if (!range.empty()) rip_ranges.push_back(range);
    }

    detail::ThreadFreezer freezer(state_->freeze_threads);
    if (state_->freeze_threads) {
        auto frozen = freezer.freeze();
        if (!frozen) return std::unexpected(frozen.error());
        if (freezer.any_rip_in(rip_ranges)) {
            return fail(ErrorCode::busy, "a suspended thread is executing inside the patch range");
        }
    }

    auto guard = detail::ProtectionGuard::make(ranges);
    if (!guard) return std::unexpected(guard.error());

    // Remove the entry jump first, so a code-cave springboard is no longer
    // reachable before its padding is restored.
    auto restore_writes = state_->writes;
    if (state_->entry_address) {
        std::stable_partition(restore_writes.begin(), restore_writes.end(), [this](const detail::StoredWrite& write) {
            return write.address == state_->entry_address;
        });
    }
    for (const auto& write : restore_writes) {
        if (!write.original.empty()) {
            std::memcpy(write.address, write.original.data(), write.original.size());
        }
    }
    for (const auto& range : ranges) detail::flush_instruction_cache(range);

    const auto protection = guard->restore();
    if (!protection) return std::unexpected(protection.error());
    state_->active = false;
    // The entry jump is gone and no thread was inside the relay, so the relay
    // page can be released immediately instead of waiting for the destructor.
    state_->allocations.clear();
    state_->runtime_contexts.clear();
    return success();
}

Patch& Patch::make_permanent() noexcept {
    if (state_ && state_->active) state_->permanent = true;
    return *this;
}

bool Patch::permanent() const noexcept { return state_ && state_->active && state_->permanent; }

bool Patch::active() const noexcept { return state_ && state_->active; }

void* Patch::address() const noexcept { return state_ ? state_->entry_address : nullptr; }

std::span<const std::byte> Patch::original_bytes() const noexcept {
    if (!state_ || state_->entry_original.empty()) return {};
    return state_->entry_original;
}

std::vector<WriteInfo> Patch::writes() const {
    std::vector<WriteInfo> result;
    if (!state_) return result;
    result.reserve(state_->writes.size());
    for (const auto& write : state_->writes) {
        result.push_back(WriteInfo{write.address, write.patched.size(), detail::is_executable(write.address)});
    }
    return result;
}

std::size_t Patch::size() const noexcept { return state_ ? state_->entry_size : 0; }

// ---------------------------------------------------------------------------
// Patcher
// ---------------------------------------------------------------------------

Patcher::Patcher() : state_(std::make_unique<detail::PlanState>()) {}
Patcher::~Patcher()                             = default;
Patcher::Patcher(Patcher&&) noexcept            = default;
Patcher& Patcher::operator=(Patcher&&) noexcept = default;

Patcher& Patcher::in(Range range) {
    state_->query.in(range);
    return *this;
}

Patcher& Patcher::in(Module module) {
    state_->query.in(std::move(module));
    return *this;
}

Patcher& Patcher::in_main_module() {
    state_->query.in_main_module();
    return *this;
}

Patcher& Patcher::in_process(bool enabled) {
    state_->query.in_process(enabled);
    return *this;
}

Patcher& Patcher::executable_only(bool enabled) {
    state_->query.executable_only(enabled);
    return *this;
}

Patcher& Patcher::alignment(std::size_t alignment) {
    state_->query.alignment(alignment);
    return *this;
}

Patcher& Patcher::unique(bool enabled) {
    if (enabled && state_->mode == detail::PlanMode::absolute) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "unique() requires a signature search");
        return *this;
    }
    if (enabled && state_->mode == detail::PlanMode::resolved && !state_->unique) {
        detail::set_error(
            *state_,
            ErrorCode::invalid_argument,
            "unique() must be called before the signature is resolved"
        );
        return *this;
    }
    state_->unique = enabled;
    return *this;
}

Patcher& Patcher::offset(std::ptrdiff_t value) {
    if (!state_->error.ok()) return *this;
    auto sum = detail::add_offsets(state_->pending_offset, value);
    if (!sum) {
        detail::set_error(*state_, sum.error());
        return *this;
    }
    state_->pending_offset = *sum;
    if (state_->mode == detail::PlanMode::resolved && state_->base) {
        auto cursor = detail::offset_address(state_->base, state_->pending_offset);
        if (!cursor) detail::set_error(*state_, cursor.error());
        else state_->cursor = *cursor;
    }
    return *this;
}

Patcher& Patcher::rel32(std::ptrdiff_t displacement_offset, std::ptrdiff_t next_instruction_offset) {
    if (!detail::ensure_resolved(*state_)) return *this;
    auto target = MatchResult(state_->cursor).rel32(displacement_offset, next_instruction_offset);
    if (!target) detail::set_error(*state_, target.error());
    else {
        state_->base           = target.address();
        state_->cursor         = target.address();
        state_->pending_offset = 0;
    }
    return *this;
}

Patcher& Patcher::at(void* address) {
    state_->mode           = detail::PlanMode::absolute;
    state_->base           = static_cast<std::byte*>(address);
    state_->match          = state_->base;
    state_->cursor         = state_->base;
    state_->pending_offset = 0;
    if (!address) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "patch address is null");
    }
    return *this;
}

Patcher& Patcher::then(std::string_view signature, std::size_t gap_min, std::size_t gap_max) {
    if (state_->mode != detail::PlanMode::pattern) {
        detail::set_error(
            *state_,
            ErrorCode::invalid_argument,
            "then() can only be used while building a search pattern"
        );
        return *this;
    }
    auto parsed = Pattern::parse(signature);
    if (!parsed) {
        detail::set_error(*state_, parsed.error());
        return *this;
    }
    state_->pattern.then(std::move(*parsed), gap_min, gap_max);
    return *this;
}

Patcher& Patcher::then(Pattern pattern, std::size_t gap_min, std::size_t gap_max) {
    if (state_->mode != detail::PlanMode::pattern) {
        detail::set_error(
            *state_,
            ErrorCode::invalid_argument,
            "then() can only be used while building a search pattern"
        );
        return *this;
    }
    state_->pattern.then(std::move(pattern), gap_min, gap_max);
    return *this;
}

Patcher& Patcher::within(std::size_t gap_min, std::size_t gap_max) {
    if (state_->mode != detail::PlanMode::pattern) {
        detail::set_error(
            *state_,
            ErrorCode::invalid_argument,
            "within() can only be used while building a search pattern"
        );
        return *this;
    }
    state_->pattern.within(gap_min, gap_max);
    return *this;
}

Patcher& Patcher::search_end() {
    // Resolution errors are recorded in state_ and reported by apply().
    std::ignore = detail::ensure_resolved(*state_);
    return *this;
}

Patcher& Patcher::write(std::span<const std::byte> data) {
    if (data.empty()) return *this;
    const auto resolved = detail::ensure_resolved(*state_);
    if (!resolved) return *this;

    std::optional<std::vector<std::byte>> expected;
    if (state_->pending_expected) {
        expected = std::move(state_->pending_expected);
        state_->pending_expected.reset();
        if (expected->size() != data.size()) {
            detail::set_error(*state_, ErrorCode::invalid_argument, "expect() size does not match write() size");
            return *this;
        }
    }

    std::vector<std::byte> bytes(data.begin(), data.end());
    detail::add_write(*state_, state_->cursor, std::move(bytes), std::move(expected));
    state_->cursor += data.size();
    detail::sync_offset(*state_);
    return *this;
}

Patcher& Patcher::write(std::span<const std::uint8_t> data) {
    return write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()));
}

Patcher& Patcher::write(std::initializer_list<std::uint8_t> data) {
    return write(std::span<const std::uint8_t>(data.begin(), data.size()));
}

Patcher& Patcher::write(std::initializer_list<std::byte> data) {
    return write(std::span<const std::byte>(data.begin(), data.size()));
}

Patcher& Patcher::write_springboard(std::size_t original_length, std::span<const std::byte> data) {
    detail::auto_write_springboard(*state_, original_length, data);
    return *this;
}

Patcher& Patcher::write_springboard(std::size_t original_length, std::span<const std::uint8_t> data) {
    return write_springboard(
        original_length,
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size())
    );
}

Patcher& Patcher::write_springboard(std::size_t original_length, std::initializer_list<std::uint8_t> data) {
    return write_springboard(original_length, std::span<const std::uint8_t>(data.begin(), data.size()));
}

Patcher& Patcher::write_springboard(std::size_t original_length, std::initializer_list<std::byte> data) {
    return write_springboard(original_length, std::span<const std::byte>(data.begin(), data.size()));
}

Patcher& Patcher::write_springboard(std::span<const std::byte> data) {
    detail::auto_write_springboard(*state_, data);
    return *this;
}

Patcher& Patcher::write_springboard(std::span<const std::uint8_t> data) {
    return write_springboard(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()));
}

Patcher& Patcher::write_springboard(std::initializer_list<std::uint8_t> data) {
    return write_springboard(std::span<const std::uint8_t>(data.begin(), data.size()));
}

Patcher& Patcher::write_springboard(std::initializer_list<std::byte> data) {
    return write_springboard(std::span<const std::byte>(data.begin(), data.size()));
}

Patcher& Patcher::springboard(std::size_t original_length, SpringboardBuilder body) {
    if (!state_->error.ok()) return *this;
    if (!body) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "springboard requires a body");
        return *this;
    }

    const auto resolved = detail::ensure_resolved(*state_);
    if (!resolved) return *this;
    if (original_length == 0) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "springboard requires a non-zero original length");
        return *this;
    }

    auto*      site       = state_->cursor;
    const auto site_value = reinterpret_cast<std::uintptr_t>(site);
    if (original_length > std::numeric_limits<std::uintptr_t>::max() - site_value) {
        detail::set_error(*state_, ErrorCode::out_of_range, "original length overflows the patch address");
        return *this;
    }
    auto* resume = reinterpret_cast<std::byte*>(site_value + original_length);

    auto expected = detail::take_pending_expected(*state_);
    if (expected && expected->size() != original_length) {
        detail::set_error(
            *state_,
            ErrorCode::invalid_argument,
            "expect() size does not match the springboard original length"
        );
        return *this;
    }
    if (expected) {
        state_->checks.push_back(detail::PlannedCheck{site, std::move(*expected)});
    }

    // The builder emits instructions at their final relay address, so relative
    // branches inside the body can be encoded by the normal instruction API.
    if (original_length < 5 || !detail::is_readable(site, 5)) {
        detail::set_error(
            *state_,
            ErrorCode::insufficient_space,
            "springboard body requires at least five readable bytes at the site"
        );
        return *this;
    }

    auto allocation = detail::allocate_near(site, detail::kRelayPageSize);
    if (!allocation) {
        detail::set_error(*state_, allocation.error());
        return *this;
    }
    auto*      relay    = static_cast<std::byte*>(allocation->data());
    const auto distance = reinterpret_cast<std::int64_t>(relay) - (reinterpret_cast<std::int64_t>(site) + 5);
    if (!detail::fits_i32(distance)) {
        detail::set_error(
            *state_,
            ErrorCode::out_of_range,
            "could not allocate a springboard relay within rel32 range"
        );
        return *this;
    }

    Patcher builder;
    builder.state_->mode           = detail::PlanMode::absolute;
    builder.state_->base           = relay;
    builder.state_->match          = relay;
    builder.state_->cursor         = relay;
    builder.state_->pending_offset = 0;

    body(builder);

    if (!builder.state_->error.ok()) {
        detail::set_error(*state_, builder.state_->error);
        return *this;
    }
    if (!builder.state_->allocations.empty()) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "springboard body must not create nested relays");
        return *this;
    }
    if (!builder.state_->checks.empty()) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "expect() is not supported inside a springboard body");
        return *this;
    }
    if (builder.state_->pending_expected) {
        detail::set_error(
            *state_,
            ErrorCode::invalid_argument,
            "expect() inside a springboard body must precede a write"
        );
        return *this;
    }
    if (builder.state_->writes.empty()) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "springboard body emitted no instructions");
        return *this;
    }

    std::vector<std::byte> stub;
    for (const auto& write : builder.state_->writes) {
        if (write.address != relay + stub.size()) {
            detail::set_error(
                *state_,
                ErrorCode::invalid_argument,
                "springboard body must write a contiguous instruction stream"
            );
            return *this;
        }
        if (write.expected) {
            detail::set_error(
                *state_,
                ErrorCode::invalid_argument,
                "expect() is not supported inside a springboard body"
            );
            return *this;
        }
        stub.insert(stub.end(), write.bytes.begin(), write.bytes.end());
    }
    if (builder.state_->cursor != relay + stub.size()) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "springboard body left an unwritten gap");
        return *this;
    }

    auto back = detail::jump_stub(relay + stub.size(), resume);
    if (back.empty()) {
        detail::set_error(*state_, ErrorCode::out_of_range, "springboard body cannot reach the resume address");
        return *this;
    }
    stub.insert(stub.end(), back.begin(), back.end());
    if (stub.size() > detail::kRelayPageSize) {
        detail::set_error(*state_, ErrorCode::insufficient_space, "springboard body is larger than its relay page");
        return *this;
    }

    const auto written = detail::write_memory(relay, stub);
    if (!written) {
        detail::set_error(*state_, written.error());
        return *this;
    }

    auto entry = detail::relative_jump(site, relay);
    if (entry.empty()) {
        detail::set_error(*state_, ErrorCode::out_of_range, "springboard relay is outside rel32 range");
        return *this;
    }

    state_->allocations.push_back(std::move(*allocation));
    detail::add_write(*state_, site, std::move(entry));
    state_->freeze_threads = true;
    state_->cursor         = resume;
    detail::sync_offset(*state_);
    return *this;
}

Patcher& Patcher::springboard(SpringboardBuilder body) {
    if (!state_->error.ok()) return *this;
    const auto resolved = detail::ensure_resolved(*state_);
    if (!resolved) return *this;

    auto* site   = state_->cursor;
    auto  region = detail::committed_region(site);
    if (!region) {
        detail::set_error(*state_, region.error());
        return *this;
    }

    const std::size_t available = std::min<std::size_t>(15, region->size());
    auto              code      = detail::read_memory(site, available);
    if (!code) {
        detail::set_error(*state_, code.error());
        return *this;
    }

    detail::Insn instruction;
    if (!detail::decode_one(reinterpret_cast<const std::uint8_t*>(code->data()), code->size(), instruction)
        || instruction.length == 0) {
        detail::set_error(
            *state_,
            ErrorCode::decode_failed,
            "cannot decode the original instruction for the springboard"
        );
        return *this;
    }

    return springboard(instruction.length, std::move(body));
}

Patcher& Patcher::guard_null(x64::Reg reg, void* if_null) {
    detail::auto_guard_null(*state_, reg, if_null);
    return *this;
}

Patcher& Patcher::fill(std::size_t count, std::uint8_t value) {
    if (count == 0) return *this;
    std::vector<std::byte> bytes(count, static_cast<std::byte>(value));
    return write(bytes);
}

Patcher& Patcher::replace_branch(x64::Branch branch) {
    if (!detail::ensure_resolved(*state_)) return *this;
    const auto kind = static_cast<unsigned>(branch);
    if (kind > static_cast<unsigned>(x64::Branch::jmp)) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "invalid branch mnemonic");
        return *this;
    }
    auto read = [&](std::size_t size) {
        auto bytes = detail::read_memory(state_->cursor, size);
        if (!bytes) detail::set_error(*state_, bytes.error());
        return bytes;
    };
    auto head = read(1);
    if (!head) return *this;
    const auto  opcode = std::to_integer<unsigned>((*head)[0]);
    std::size_t length = 0;
    if ((opcode >= 0x70 && opcode <= 0x7f) || opcode == 0xeb) length = 2;
    else if (opcode == 0xe9) length = 5;
    else if (opcode == 0x0f) {
        head = read(2);
        if (!head) return *this;
        const auto second = std::to_integer<unsigned>((*head)[1]);
        if (second >= 0x80 && second <= 0x8f) length = 6;
    }
    if (!length) {
        detail::set_error(
            *state_,
            ErrorCode::unsupported_instruction,
            "replace_branch requires an unprefixed direct Jcc or JMP"
        );
        return *this;
    }
    auto original = read(length);
    if (!original) return *this;
    auto       bytes = *original;
    const bool jump  = branch == x64::Branch::jmp;
    if (length == 2) {
        bytes[0] = static_cast<std::byte>(jump ? 0xeb : 0x70 + kind);
    } else if (!jump) {
        if (length == 5) {
            detail::set_error(
                *state_,
                ErrorCode::insufficient_space,
                "near Jcc needs six bytes; original JMP has five"
            );
            return *this;
        }
        bytes[1] = static_cast<std::byte>(0x80 + kind);
    } else if (length == 6) {
        std::int32_t displacement{};
        std::memcpy(&displacement, original->data() + 2, sizeof(displacement));
        if (displacement == std::numeric_limits<std::int32_t>::max()) {
            detail::set_error(*state_, ErrorCode::out_of_range, "preserving branch target would overflow rel32");
            return *this;
        }
        ++displacement; // JMP ends one byte before the original Jcc.
        bytes[0] = std::byte{0xe9};
        std::memcpy(bytes.data() + 1, &displacement, sizeof(displacement));
        bytes[5] = std::byte{0x90};
    }
    // Keep an explicit expect() as well as the bytes used to calculate target.
    state_->checks.push_back(detail::PlannedCheck{state_->cursor, std::move(*original)});
    return write(bytes);
}

Patcher& Patcher::skip(std::ptrdiff_t count) { return offset(count); }

Patcher& Patcher::write_at(void* address, std::span<const std::byte> data) {
    if (!address && !data.empty()) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "write_at address is null");
        return *this;
    }
    detail::add_write(*state_, static_cast<std::byte*>(address), std::vector<std::byte>(data.begin(), data.end()));
    return *this;
}

Patcher& Patcher::write_at(void* address, std::initializer_list<std::uint8_t> data) {
    return write_at(address, std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.begin()), data.size()));
}

Patcher& Patcher::expect(std::span<const std::byte> data) {
    state_->pending_expected = std::vector<std::byte>(data.begin(), data.end());
    return *this;
}

Patcher& Patcher::expect(std::initializer_list<std::uint8_t> data) {
    return expect(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.begin()), data.size()));
}

Patcher& Patcher::verify(bool enabled) {
    state_->verify = enabled;
    return *this;
}

Patcher& Patcher::freeze_threads(bool enabled) {
    state_->freeze_threads = enabled;
    return *this;
}

Patcher& Patcher::runtime(RuntimeCallback callback) {
    if (!callback) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "runtime() requires a callback");
        return *this;
    }
    auto holder = std::make_shared<detail::RuntimeCallableHolder<RuntimeCallback>>(
        detail::RuntimeCallableHolder<RuntimeCallback>{callback}
    );
    auto* context = holder.get();
    return runtime_callable(&detail::invoke_runtime_callable<RuntimeCallback>, context, std::move(holder));
}

Patcher& Patcher::runtime_callable(RuntimeInvoker invoker, void* context, std::shared_ptr<void> owner) {
    if (!invoker || !owner) {
        detail::set_error(*state_, ErrorCode::invalid_argument, "runtime() requires a callback");
        return *this;
    }
    const auto resolved = detail::ensure_resolved(*state_);
    if (!resolved) return *this;

    auto region = detail::committed_region(state_->cursor);
    if (!region) {
        detail::set_error(*state_, region.error());
        return *this;
    }
    std::size_t original_length = 0;
    while (original_length < 5) {
        const auto address = state_->cursor + original_length;
        if (address >= region->end) {
            detail::set_error(
                *state_,
                ErrorCode::insufficient_space,
                "runtime() reached the end of the readable region"
            );
            return *this;
        }
        const auto   available = std::min<std::size_t>(15, region->end - address);
        detail::Insn instruction;
        if (!detail::decode_one(reinterpret_cast<const std::uint8_t*>(address), available, instruction)) {
            detail::set_error(
                *state_,
                ErrorCode::decode_failed,
                "runtime() cannot decode the instruction at the patch point"
            );
            return *this;
        }
        if (instruction.rip_relative || instruction.is_branch()) {
            detail::set_error(
                *state_,
                ErrorCode::unsupported_instruction,
                "runtime() cannot relocate RIP-relative or control-flow instructions"
            );
            return *this;
        }
        original_length += instruction.length;
    }

    auto original = detail::read_memory(state_->cursor, original_length);
    if (!original) {
        detail::set_error(*state_, original.error());
        return *this;
    }
    auto thunk = detail::make_runtime_thunk(state_->cursor, invoker, context);
    if (!thunk) {
        detail::set_error(*state_, thunk.error());
        return *this;
    }
    state_->allocations.push_back(std::move(*thunk));
    state_->runtime_contexts.push_back(std::move(owner));
    auto*      callback_thunk = state_->allocations.back().data();
    const auto original_bytes = std::move(*original);

    // The springboard invokes the runtime callback before executing the
    // original instruction, then resumes at the instruction after the site.
    springboard(original_length, [callback_thunk, original_bytes](Patcher& p) {
        p.call(callback_thunk).write(std::span<const std::byte>(original_bytes.data(), original_bytes.size()));
    });
    return *this;
}

Patcher& Patcher::jmp(void* target) {
    detail::auto_jmp(*state_, target);
    return *this;
}

Patcher& Patcher::jmp_short(void* target) {
    detail::emit(*state_, [target](detail::Emitter& emitter) { detail::emit_jmp(emitter, target, true); });
    return *this;
}

Patcher& Patcher::jmp_abs(void* target) {
    detail::auto_jmp_abs(*state_, target);
    return *this;
}

Patcher& Patcher::call(void* target) {
    detail::auto_call(*state_, target);
    return *this;
}

Patcher& Patcher::ret() {
    detail::emit(*state_, [](detail::Emitter& emitter) { detail::emit_ret(emitter); });
    return *this;
}

Patcher& Patcher::int3() {
    detail::emit(*state_, [](detail::Emitter& emitter) { detail::emit_int3(emitter); });
    return *this;
}

Patcher& Patcher::nop(std::size_t count) {
    detail::emit(*state_, [count](detail::Emitter& emitter) {
        for (std::size_t i = 0; i < count; ++i) detail::emit_nop(emitter);
    });
    return *this;
}

Patcher& Patcher::push(x64::Reg reg) {
    detail::emit(*state_, [reg](detail::Emitter& emitter) { detail::emit_push_pop(emitter, reg, true); });
    return *this;
}

Patcher& Patcher::pop(x64::Reg reg) {
    detail::emit(*state_, [reg](detail::Emitter& emitter) { detail::emit_push_pop(emitter, reg, false); });
    return *this;
}

Patcher& Patcher::mov(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) { detail::emit_mov_reg_reg(emitter, dst, src); });
    return *this;
}

Patcher& Patcher::mov(x64::Reg dst, std::int64_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) { detail::emit_mov_reg_imm(emitter, dst, imm); });
    return *this;
}

Patcher& Patcher::mov(x64::Reg dst, x64::Mem src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) { detail::emit_mov_reg_mem(emitter, dst, src); });
    return *this;
}

Patcher& Patcher::mov(x64::Mem dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) { detail::emit_mov_mem_reg(emitter, dst, src); });
    return *this;
}

Patcher& Patcher::mov(x64::Mem dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) { detail::emit_mov_mem_imm(emitter, dst, imm); });
    return *this;
}

Patcher& Patcher::lea(x64::Reg dst, x64::Mem src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) { detail::emit_lea(emitter, dst, src); });
    return *this;
}

Patcher& Patcher::add(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) {
        detail::emit_alu_reg_reg(emitter, detail::AluOp::add, dst, src);
    });
    return *this;
}

Patcher& Patcher::add(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) {
        detail::emit_alu_reg_imm(emitter, detail::AluOp::add, dst, imm);
    });
    return *this;
}

Patcher& Patcher::sub(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) {
        detail::emit_alu_reg_reg(emitter, detail::AluOp::sub, dst, src);
    });
    return *this;
}

Patcher& Patcher::sub(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) {
        detail::emit_alu_reg_imm(emitter, detail::AluOp::sub, dst, imm);
    });
    return *this;
}

Patcher& Patcher::and_(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) {
        detail::emit_alu_reg_reg(emitter, detail::AluOp::and_, dst, src);
    });
    return *this;
}

Patcher& Patcher::and_(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) {
        detail::emit_alu_reg_imm(emitter, detail::AluOp::and_, dst, imm);
    });
    return *this;
}

Patcher& Patcher::or_(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) {
        detail::emit_alu_reg_reg(emitter, detail::AluOp::or_, dst, src);
    });
    return *this;
}

Patcher& Patcher::or_(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) {
        detail::emit_alu_reg_imm(emitter, detail::AluOp::or_, dst, imm);
    });
    return *this;
}

Patcher& Patcher::xor_(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) {
        detail::emit_alu_reg_reg(emitter, detail::AluOp::xor_, dst, src);
    });
    return *this;
}

Patcher& Patcher::xor_(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) {
        detail::emit_alu_reg_imm(emitter, detail::AluOp::xor_, dst, imm);
    });
    return *this;
}

Patcher& Patcher::cmp(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) {
        detail::emit_alu_reg_reg(emitter, detail::AluOp::cmp, dst, src);
    });
    return *this;
}

Patcher& Patcher::cmp(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) {
        detail::emit_alu_reg_imm(emitter, detail::AluOp::cmp, dst, imm);
    });
    return *this;
}

Patcher& Patcher::test(x64::Reg dst, x64::Reg src) {
    detail::emit(*state_, [dst, src](detail::Emitter& emitter) { detail::emit_test_reg_reg(emitter, dst, src); });
    return *this;
}

Patcher& Patcher::test(x64::Reg dst, std::int32_t imm) {
    detail::emit(*state_, [dst, imm](detail::Emitter& emitter) { detail::emit_test_reg_imm(emitter, dst, imm); });
    return *this;
}

Patcher& Patcher::inc(x64::Reg dst) {
    detail::emit(*state_, [dst](detail::Emitter& emitter) { detail::emit_inc_dec(emitter, dst, true); });
    return *this;
}

Patcher& Patcher::dec(x64::Reg dst) {
    detail::emit(*state_, [dst](detail::Emitter& emitter) { detail::emit_inc_dec(emitter, dst, false); });
    return *this;
}

namespace {
Patcher& emit_jcc(Patcher& patcher, detail::PlanState& state, std::uint8_t condition, void* target) {
    detail::emit(state, [condition, target](detail::Emitter& emitter) {
        detail::emit_jcc(emitter, condition, target);
    });
    return patcher;
}
} // namespace

Patcher& Patcher::je(void* target) { return emit_jcc(*this, *state_, 0x4, target); }
Patcher& Patcher::jne(void* target) { return emit_jcc(*this, *state_, 0x5, target); }
Patcher& Patcher::jg(void* target) { return emit_jcc(*this, *state_, 0xF, target); }
Patcher& Patcher::jge(void* target) { return emit_jcc(*this, *state_, 0xD, target); }
Patcher& Patcher::jl(void* target) { return emit_jcc(*this, *state_, 0xC, target); }
Patcher& Patcher::jle(void* target) { return emit_jcc(*this, *state_, 0xE, target); }
Patcher& Patcher::ja(void* target) { return emit_jcc(*this, *state_, 0x7, target); }
Patcher& Patcher::jae(void* target) { return emit_jcc(*this, *state_, 0x3, target); }
Patcher& Patcher::jb(void* target) { return emit_jcc(*this, *state_, 0x2, target); }
Patcher& Patcher::jbe(void* target) { return emit_jcc(*this, *state_, 0x6, target); }
Patcher& Patcher::js(void* target) { return emit_jcc(*this, *state_, 0x8, target); }
Patcher& Patcher::jns(void* target) { return emit_jcc(*this, *state_, 0x9, target); }

MatchResult Patcher::find() {
    const auto resolved = detail::ensure_resolved(*state_);
    if (!resolved) return MatchResult(state_->error);
    return MatchResult(state_->base);
}

Result<Match> Patcher::require_find() {
    auto result = find();
    if (!result) return std::unexpected(result.error());
    return Match{result.address(), 0, state_->pattern.name()};
}

MatchResult Patcher::cursor() {
    if (!detail::ensure_resolved(*state_)) return MatchResult(state_->error);
    return MatchResult(state_->cursor);
}

Result<Patch> Patcher::apply() {
    if (state_->applied) {
        return fail(ErrorCode::invalid_argument, "patch plan has already been applied");
    }
    const auto resolved = detail::ensure_resolved(*state_);
    if (!resolved) return std::unexpected(state_->error);
    if (state_->writes.empty()) {
        return fail(ErrorCode::invalid_argument, "patch plan has no writes");
    }

    // Sort and reject overlapping writes. Overlap almost always means the
    // caller made a mistake in offsets, and silently applying it would make
    // restoration ambiguous.
    auto sorted = state_->writes;
    std::sort(sorted.begin(), sorted.end(), [](const detail::PlannedWrite& a, const detail::PlannedWrite& b) {
        return a.address < b.address;
    });
    for (std::size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i - 1].address + sorted[i - 1].bytes.size() > sorted[i].address) {
            return fail(
                ErrorCode::overlap,
                "patch writes overlap at " + detail::hex(reinterpret_cast<std::uintptr_t>(sorted[i].address))
            );
        }
    }

    std::vector<detail::StoredWrite> stored;
    stored.reserve(sorted.size());
    std::vector<Range> ranges;
    ranges.reserve(sorted.size());

    for (const auto& write : sorted) {
        auto original = detail::read_memory(write.address, write.bytes.size());
        if (!original) return std::unexpected(original.error());
        if (state_->verify && write.expected) {
            if (original->size() != write.expected->size()
                || std::memcmp(original->data(), write.expected->data(), original->size()) != 0) {
                return fail(
                    ErrorCode::verify_failed,
                    "expected bytes do not match at " + detail::hex(reinterpret_cast<std::uintptr_t>(write.address))
                );
            }
        }
        ranges.push_back(Range::from(write.address, write.bytes.size()));
        stored.push_back(detail::StoredWrite{write.address, std::move(*original), write.bytes});
    }

    // `expect()` on a springboard/guard checks the original range, which is
    // generally larger than the entry jump written at the site.
    if (state_->verify) {
        for (const auto& check : state_->checks) {
            auto original = detail::read_memory(check.address, check.expected.size());
            if (!original) return std::unexpected(original.error());
            if (original->size() != check.expected.size()
                || std::memcmp(original->data(), check.expected.data(), check.expected.size()) != 0) {
                return fail(
                    ErrorCode::verify_failed,
                    "expected bytes do not match at " + detail::hex(reinterpret_cast<std::uintptr_t>(check.address))
                );
            }
        }
    }

    detail::ThreadFreezer freezer(state_->freeze_threads);
    if (state_->freeze_threads) {
        auto frozen = freezer.freeze();
        if (!frozen) return std::unexpected(frozen.error());
        if (freezer.any_rip_in(ranges)) {
            return fail(ErrorCode::busy, "a suspended thread is executing inside the patch range");
        }
    }

    auto guard = detail::ProtectionGuard::make(ranges);
    if (!guard) return std::unexpected(guard.error());

    // Build non-entry writes (relay/cave stubs) first and commit the entry
    // jump last. With frozen threads no thread can observe the intermediate
    // state, but this ordering also makes the intent explicit.
    auto commit_writes = stored;
    if (state_->entry_address) {
        std::stable_partition(commit_writes.begin(), commit_writes.end(), [this](const detail::StoredWrite& write) {
            return write.address != state_->entry_address;
        });
    }
    for (const auto& write : commit_writes) {
        std::memcpy(write.address, write.patched.data(), write.patched.size());
    }
    for (const auto& range : ranges) detail::flush_instruction_cache(range);

    const auto protection = guard->restore();
    if (!protection) return std::unexpected(protection.error());

    auto patch_state              = std::make_unique<detail::PatchState>();
    patch_state->active           = true;
    patch_state->freeze_threads   = state_->freeze_threads;
    patch_state->allocations      = std::move(state_->allocations);
    patch_state->runtime_contexts = std::move(state_->runtime_contexts);
    patch_state->entry_address    = state_->entry_address;
    patch_state->entry_size       = state_->entry_size;
    if (!patch_state->entry_address && !sorted.empty()) {
        patch_state->entry_address = sorted.front().address;
    }
    if (patch_state->entry_address) {
        for (const auto& write : stored) {
            if (write.address == patch_state->entry_address) {
                patch_state->entry_original = write.original;
                patch_state->entry_size     = write.original.size();
                break;
            }
        }
    }
    patch_state->writes = std::move(stored);
    state_->applied     = true;
    return Patch(std::move(patch_state));
}

Result<Patch> Patcher::apply_permanent() {
    auto patch = apply();
    if (!patch) return std::unexpected(patch.error());
    patch->make_permanent();
    return patch;
}

const Error& Patcher::last_error() const noexcept {
    static const Error none{};
    return state_ ? state_->error : none;
}

bool Patcher::ok() const noexcept { return state_ && state_->error.ok(); }

} // namespace ipatch
