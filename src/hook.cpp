// SPDX-License-Identifier: MIT
#include "ipatch/hook.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "ipatch/module.hpp"

#include "decoder.hpp"
#include "memory.hpp"
#include "relocation.hpp"
#include "threads.hpp"
#include "win.hpp"

namespace ipatch {
namespace detail {

thread_local void* active_hook_context = nullptr;

IPATCH_API void* get_active_hook_context() noexcept { return active_hook_context; }

IPATCH_API void clear_active_hook_context() noexcept { active_hook_context = nullptr; }

struct HookState {
    bool        installed{false};
    void*       target{nullptr};
    void*       detour{nullptr};
    void*       trampoline{nullptr};
    void*       relay{nullptr};
    std::size_t stolen{0};
    std::size_t patch_size{0};
    bool        uses_relay{false};

    Allocation             allocation;
    std::vector<std::byte> original;
    std::vector<Range>     patched_ranges;

    void* callback_context{nullptr};
    void (*callback_destroy)(void*) noexcept {nullptr};
    Allocation callback_allocation;

    ~HookState() {
        if (callback_destroy && callback_context) callback_destroy(callback_context);
    }

    Status remove();
};

namespace {

constexpr std::size_t kPage             = 0x1000;
constexpr std::size_t kRelayOffset      = 0;
constexpr std::size_t kTrampolineOffset = 0x100;

[[nodiscard]] bool fits_i32(std::int64_t value) noexcept {
    return value >= std::numeric_limits<std::int32_t>::min() && value <= std::numeric_limits<std::int32_t>::max();
}

[[nodiscard]] std::vector<std::byte> absolute_jump(void* target) {
    std::vector<std::byte> bytes;
    bytes.reserve(14);
    const std::uint8_t prefix[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    for (auto b : prefix) bytes.push_back(static_cast<std::byte>(b));
    const auto value = reinterpret_cast<std::uint64_t>(target);
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFF));
    }
    return bytes;
}

[[nodiscard]] std::vector<std::byte> relative_jump(void* from, void* to, bool& ok) {
    std::vector<std::byte> bytes;
    const auto             next     = reinterpret_cast<std::int64_t>(from) + 5;
    const auto             relative = reinterpret_cast<std::int64_t>(to) - next;
    if (!fits_i32(relative)) {
        ok = false;
        return bytes;
    }
    ok = true;
    bytes.push_back(std::byte{0xE9});
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<std::byte>((static_cast<std::uint32_t>(relative) >> (i * 8)) & 0xFF));
    }
    return bytes;
}

struct Stolen {
    std::size_t       length{0};
    std::vector<Insn> instructions;
};

[[nodiscard]] Result<Stolen> compute_stolen(void* target, std::size_t minimum) {
    auto region = committed_region(target);
    if (!region) return std::unexpected(region.error());
    if (!is_readable(target, std::min<std::size_t>(15, region->size()))) {
        return fail(ErrorCode::access_denied, "target prologue is not readable");
    }

    const auto* code       = static_cast<const std::uint8_t*>(target);
    const auto  base       = reinterpret_cast<std::uintptr_t>(target);
    const auto  region_end = reinterpret_cast<std::uintptr_t>(region->end);
    Stolen      result;
    std::size_t offset = 0;
    while (offset < minimum) {
        const auto address = base + offset;
        if (address >= region_end) {
            return fail(
                ErrorCode::insufficient_space,
                "target prologue ends before " + std::to_string(minimum) + " bytes"
            );
        }
        const std::size_t available = std::min<std::size_t>(15, region_end - address);
        Insn              insn;
        if (!decode_one(code + offset, available, insn)) {
            return fail(ErrorCode::decode_failed, "cannot decode target instruction at +" + std::to_string(offset));
        }
        result.instructions.push_back(insn);
        offset += insn.length;
        if (result.instructions.size() > 64 || offset > 128) {
            return fail(ErrorCode::insufficient_space, "target prologue is unreasonably large");
        }
    }
    result.length = offset;
    return result;
}

extern "C" void set_active_hook_context(void* context) noexcept { detail::active_hook_context = context; }

void append_u32(std::vector<std::byte>& code, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) {
        code.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFF));
    }
}

void append_u64(std::vector<std::byte>& code, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        code.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFF));
    }
}

void mov_store_reg(std::vector<std::byte>& code, unsigned reg, std::uint8_t offset) {
    // mov [rsp + disp8], reg. The thunk only stores the four Windows x64
    // integer argument registers, so the compact disp8 form is sufficient.
    code.insert(
        code.end(),
        {static_cast<std::byte>(reg < 8 ? 0x48 : 0x4C),
         std::byte{0x89},
         static_cast<std::byte>(0x44 + ((reg & 7) << 3)),
         std::byte{0x24},
         static_cast<std::byte>(offset)}
    );
}

void mov_load_reg(std::vector<std::byte>& code, unsigned reg, std::uint8_t offset) {
    code.insert(
        code.end(),
        {static_cast<std::byte>(reg < 8 ? 0x48 : 0x4C),
         std::byte{0x8B},
         static_cast<std::byte>(0x44 + ((reg & 7) << 3)),
         std::byte{0x24},
         static_cast<std::byte>(offset)}
    );
}

void mov_store_xmm(std::vector<std::byte>& code, unsigned xmm, std::uint8_t offset) {
    code.insert(
        code.end(),
        {std::byte{0xF3},
         std::byte{0x0F},
         std::byte{0x7F},
         std::byte{0x44},
         std::byte{0x24},
         static_cast<std::byte>(offset)}
    );
    code[code.size() - 3] = static_cast<std::byte>(0x44 + (xmm << 3));
}

void mov_load_xmm(std::vector<std::byte>& code, unsigned xmm, std::uint8_t offset) {
    code.insert(
        code.end(),
        {std::byte{0xF3},
         std::byte{0x0F},
         std::byte{0x6F},
         std::byte{0x44},
         std::byte{0x24},
         static_cast<std::byte>(offset)}
    );
    code[code.size() - 3] = static_cast<std::byte>(0x44 + (xmm << 3));
}

[[nodiscard]] Result<Allocation> make_callable_thunk(void* target, void* context, void* adapter) {
    auto allocation = allocate_near(target, kPage);
    if (!allocation) return std::unexpected(allocation.error());

    std::vector<std::byte> code;
    code.reserve(128);
    // Keep the original stack arguments at their original offsets while the
    // context setter runs. 0x88 bytes preserves 16-byte call alignment.
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x81}, std::byte{0xEC}});
    append_u32(code, 0x88);
    // Register ids follow the x86 encoding: RCX=1, RDX=2, R8=8, R9=9.
    mov_store_reg(code, 1, 0x20);
    mov_store_reg(code, 2, 0x28);
    mov_store_reg(code, 8, 0x30);
    mov_store_reg(code, 9, 0x38);
    for (unsigned i = 0; i < 4; ++i) mov_store_xmm(code, i, static_cast<std::uint8_t>(0x40 + i * 0x10));

    code.insert(code.end(), {std::byte{0x48}, std::byte{0xB9}});
    append_u64(code, reinterpret_cast<std::uint64_t>(context));
    code.insert(code.end(), {std::byte{0x48}, std::byte{0xB8}});
    append_u64(code, reinterpret_cast<std::uint64_t>(&set_active_hook_context));
    code.insert(code.end(), {std::byte{0xFF}, std::byte{0xD0}}); // call rax

    for (unsigned i = 0; i < 4; ++i) mov_load_xmm(code, i, static_cast<std::uint8_t>(0x40 + i * 0x10));
    mov_load_reg(code, 1, 0x20);
    mov_load_reg(code, 2, 0x28);
    mov_load_reg(code, 8, 0x30);
    mov_load_reg(code, 9, 0x38);
    code.insert(code.end(), {std::byte{0x48}, std::byte{0x81}, std::byte{0xC4}});
    append_u32(code, 0x88);
    // jmp qword ptr [rip+0], followed by the adapter address.
    code.insert(
        code.end(),
        {std::byte{0xFF}, std::byte{0x25}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}}
    );
    append_u64(code, reinterpret_cast<std::uint64_t>(adapter));

    if (code.size() > allocation->size()) {
        return fail(ErrorCode::allocation_failed, "typed hook thunk does not fit");
    }
    std::memcpy(allocation->data(), code.data(), code.size());
    flush_instruction_cache(Range::from(allocation->data(), code.size()));
    return allocation;
}

} // namespace

Status HookState::remove() {
    if (!installed) return success();
    if (!target || original.empty()) return fail(ErrorCode::not_installed, "hook is not installed");

    const std::vector<Range> target_ranges{Range::from(target, stolen)};
    ThreadFreezer            freezer(true);
    auto                     frozen = freezer.freeze();
    if (!frozen) return std::unexpected(frozen.error());
    if (freezer.any_rip_in(target_ranges)) {
        return fail(ErrorCode::busy, "cannot remove hook while a thread is executing in the patched prologue");
    }

    auto guard = ProtectionGuard::make(target_ranges);
    if (!guard) return std::unexpected(guard.error());
    std::memcpy(target, original.data(), original.size());
    flush_instruction_cache(target_ranges.front());
    auto restored = guard->restore();
    if (!restored) return std::unexpected(restored.error());

    installed = false;
    return success();
}

} // namespace detail

Hook::Hook() = default;
Hook::Hook(std::unique_ptr<detail::HookState> state) : state_(std::move(state)) {}

Hook::~Hook() {
    if (!state_) return;
    const auto removed = state_->remove();
    if (!removed) {
        // Never free a trampoline that may still be reachable from the target
        // prologue. Leaking one page is much safer than a dangling jump.
        state_.release();
    }
}

Hook::Hook(Hook&& other) noexcept : state_(std::move(other.state_)) {}

Hook& Hook::operator=(Hook&& other) noexcept {
    if (this != &other) {
        if (state_) {
            const auto removed = state_->remove();
            if (!removed) {
                state_.release();
            }
        }
        state_ = std::move(other.state_);
    }
    return *this;
}

Result<Hook> Hook::create_callable(
    void*           target,
    void*           context,
    void*           adapter,
    CallbackDestroy destroy,
    HookOptions     options
) {
    if (!target || !context || !adapter || !destroy) {
        return fail(ErrorCode::invalid_argument, "typed hook callback is incomplete");
    }
    auto thunk = detail::make_callable_thunk(target, context, adapter);
    if (!thunk) return std::unexpected(thunk.error());

    auto hook = create(target, thunk->data(), options);
    if (!hook) return std::unexpected(hook.error());
    hook->state_->callback_context    = context;
    hook->state_->callback_destroy    = destroy;
    hook->state_->callback_allocation = std::move(*thunk);
    return hook;
}

Result<Hook> Hook::create(void* target, void* detour, HookOptions options) {
    if (!target || !detour) {
        return fail(ErrorCode::invalid_argument, "Hook::create requires target and detour");
    }
    if (target == detour) {
        return fail(ErrorCode::invalid_argument, "target and detour are the same address");
    }
    if (!detail::is_executable(target)) {
        return fail(ErrorCode::access_denied, "target is not executable");
    }

    const auto target_address = reinterpret_cast<std::uintptr_t>(target);
    const auto detour_address = reinterpret_cast<std::uintptr_t>(detour);
    const auto direct_distance =
        static_cast<std::int64_t>(detour_address) - static_cast<std::int64_t>(target_address + 5);
    const bool direct = detail::fits_i32(direct_distance) && !options.force_relay;

    // Allocate one page near the target for the trampoline and, when needed,
    // the relay. Keeping both close means rel32 branches and RIP-relative
    // operands in the stolen prologue need no invasive rewriting.
    auto allocation = detail::allocate_near(target, detail::kPage, options.trampoline_hint);
    if (!allocation) return std::unexpected(allocation.error());

    void* relay      = nullptr;
    void* trampoline = nullptr;
    if (!direct) {
        relay                     = static_cast<std::byte*>(allocation->data()) + detail::kRelayOffset;
        const auto relay_distance = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(relay))
                                  - static_cast<std::int64_t>(target_address + 5);
        if (!detail::fits_i32(relay_distance)) {
            // The OS could not place the relay within reach. We can still use
            // a 14-byte absolute jump directly in the target if enough bytes
            // are available.
            relay = nullptr;
        }
        if (relay) {
            trampoline = static_cast<std::byte*>(allocation->data()) + detail::kTrampolineOffset;
        } else {
            trampoline = allocation->data();
        }
    } else {
        trampoline = allocation->data();
    }

    const std::size_t minimum = options.steal_bytes != 0 ? options.steal_bytes : 5;
    auto              stolen  = detail::compute_stolen(target, minimum);
    if (!stolen) return std::unexpected(stolen.error());

    std::size_t patch_size = 5;
    if (!direct && !relay) {
        patch_size = 14;
        auto wide  = detail::compute_stolen(target, patch_size);
        if (!wide) return std::unexpected(wide.error());
        stolen = std::move(wide);
    }

    if (stolen->length < patch_size) {
        return fail(ErrorCode::insufficient_space, "not enough decodable bytes for the selected jump encoding");
    }

    const auto        trampoline_address = static_cast<std::uint8_t*>(trampoline);
    const std::size_t trampoline_capacity =
        detail::kPage - static_cast<std::size_t>(trampoline_address - static_cast<std::uint8_t*>(allocation->data()));
    auto relocation = detail::relocate(
        static_cast<const std::uint8_t*>(target),
        stolen->length,
        trampoline_address,
        trampoline_capacity
    );
    if (!relocation) return std::unexpected(relocation.error());

    if (relocation->code.size() > trampoline_capacity) {
        return fail(ErrorCode::allocation_failed, "relocated trampoline does not fit");
    }
    std::memcpy(trampoline, relocation->code.data(), relocation->code.size());
    detail::flush_instruction_cache(Range::from(trampoline, relocation->code.size()));

    std::vector<std::byte> patch;
    if (direct) {
        bool ok = false;
        patch   = detail::relative_jump(target, detour, ok);
        if (!ok) return fail(ErrorCode::out_of_range, "direct jump unexpectedly out of range");
    } else if (relay) {
        const auto relay_jump = detail::absolute_jump(detour);
        std::memcpy(relay, relay_jump.data(), relay_jump.size());
        detail::flush_instruction_cache(Range::from(relay, relay_jump.size()));

        bool ok = false;
        patch   = detail::relative_jump(target, relay, ok);
        if (!ok) return fail(ErrorCode::out_of_range, "relay is not within rel32 range");
    } else {
        patch = detail::absolute_jump(detour);
    }

    // NOP the rest of the stolen bytes so partial instructions never remain.
    std::vector<std::byte> entry(stolen->length, std::byte{0x90});
    std::copy(patch.begin(), patch.end(), entry.begin());

    auto original_bytes = detail::read_memory(target, stolen->length);
    if (!original_bytes) return std::unexpected(original_bytes.error());

    const std::vector<Range> ranges{Range::from(target, stolen->length)};
    detail::ThreadFreezer    freezer(options.freeze_threads);
    if (options.freeze_threads) {
        auto frozen = freezer.freeze();
        if (!frozen) return std::unexpected(frozen.error());
    }

    auto guard = detail::ProtectionGuard::make(ranges);
    if (!guard) return std::unexpected(guard.error());
    std::memcpy(target, entry.data(), entry.size());
    detail::flush_instruction_cache(ranges.front());

    std::vector<detail::RipRemap> remaps;
    remaps.reserve(relocation->instructions.size());
    for (const auto& insn : relocation->instructions) {
        remaps.push_back(
            detail::RipRemap{
                target_address + insn.old_offset,
                target_address + insn.old_offset + insn.old_length,
                reinterpret_cast<std::uintptr_t>(trampoline_address) + insn.new_offset,
                0
            }
        );
    }
    if (options.freeze_threads) {
        auto remapped = freezer.remap_rips(remaps);
        if (!remapped) {
            std::memcpy(target, original_bytes->data(), original_bytes->size());
            detail::flush_instruction_cache(ranges.front());
            return std::unexpected(remapped.error());
        }
    }

    const auto restored = guard->restore();
    if (!restored) {
        // The protection update failed after the entry was written. Roll the
        // prologue back before returning; otherwise the target would point at
        // a trampoline that is about to be freed.
        std::memcpy(target, original_bytes->data(), original_bytes->size());
        detail::flush_instruction_cache(ranges.front());
        return std::unexpected(restored.error());
    }

    auto state            = std::make_unique<detail::HookState>();
    state->installed      = true;
    state->target         = target;
    state->detour         = detour;
    state->trampoline     = trampoline;
    state->relay          = relay;
    state->stolen         = stolen->length;
    state->patch_size     = patch_size;
    state->uses_relay     = relay != nullptr;
    state->allocation     = std::move(*allocation);
    state->original       = std::move(*original_bytes);
    state->patched_ranges = ranges;

    return Hook(std::move(state));
}

Result<Hook> Hook::create(std::string_view signature, void* detour, HookOptions options) {
    auto pattern = Pattern::parse(signature);
    if (!pattern) return std::unexpected(pattern.error());
    return create(std::move(*pattern), detour, options);
}

Result<Hook> Hook::create(Pattern pattern, void* detour, HookOptions options) {
    auto main_module = Module::main();
    if (!main_module.valid()) {
        return fail(ErrorCode::module_not_found, "main module is unavailable");
    }
    auto range = main_module.executable_range();
    if (range.empty()) {
        return fail(ErrorCode::not_found, "main module has no executable sections");
    }
    return create(std::move(pattern), range, detour, options);
}

Result<Hook> Hook::create(Pattern pattern, Range range, void* detour, HookOptions options) {
    const auto found = pattern.find_first(range);
    if (!found) {
        return fail(ErrorCode::not_found, "hook signature not found");
    }
    return create(*found, detour, options);
}

Status Hook::remove() {
    if (!state_) return success();
    return state_->remove();
}

bool Hook::installed() const noexcept { return state_ && state_->installed; }

void* Hook::target() const noexcept { return state_ ? state_->target : nullptr; }

void* Hook::detour() const noexcept { return state_ ? state_->detour : nullptr; }

void* Hook::original() const noexcept { return state_ ? state_->trampoline : nullptr; }

void* Hook::trampoline() const noexcept { return original(); }

void* Hook::relay() const noexcept { return state_ ? state_->relay : nullptr; }

std::size_t Hook::stolen_bytes() const noexcept { return state_ ? state_->stolen : 0; }

std::size_t Hook::patch_bytes() const noexcept { return state_ ? state_->patch_size : 0; }

bool Hook::uses_relay() const noexcept { return state_ && state_->uses_relay; }

} // namespace ipatch
