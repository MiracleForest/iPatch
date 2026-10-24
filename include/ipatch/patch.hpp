// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <concepts>
#include <functional>
#include <initializer_list>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "ipatch/config.hpp"
#include "ipatch/context.hpp"
#include "ipatch/error.hpp"
#include "ipatch/module.hpp"
#include "ipatch/pattern.hpp"
#include "ipatch/range.hpp"
#include "ipatch/scan.hpp"
#include "ipatch/x64.hpp"

namespace ipatch {

struct WriteInfo {
    void* address{nullptr};
    std::size_t size{0};
    bool executable{false};
};

namespace detail {
struct PlanState;
struct PatchState;
} // namespace detail

class Patcher;

/// An applied, reversible patch transaction.
///
/// The destructor restores every byte written by the transaction. Patches are
/// designed to be chained and nested: the last installed patch is restored
/// first because each Patch owns its own snapshot.
class IPATCH_API Patch {
public:
    Patch();
    ~Patch();

    Patch(const Patch&) = delete;
    Patch& operator=(const Patch&) = delete;
    Patch(Patch&& other) noexcept;
    Patch& operator=(Patch&& other) noexcept;

    [[nodiscard]] static Patcher at(void* address);
    /// Carries a failed scan/locate into apply() without losing its diagnostic.
    [[nodiscard]] static Patcher at(const MatchResult& address);
    [[nodiscard]] static Patcher at(const Result<std::byte*>& address);
    /// Starts at `rva` bytes from the module base.
    ///
    ///     auto patch = Patch::at(module, 0x1C483BC)...
    [[nodiscard]] static Patcher at(Module module, std::uintptr_t rva);
    [[nodiscard]] static Patcher search(std::string_view signature);
    [[nodiscard]] static Patcher search(Pattern pattern);
    [[nodiscard]] static Patcher search();

    /// Literal text search in readable module sections, including data.
    [[nodiscard]] static Patcher search_string(std::string_view text, bool null_terminated = false);
    [[nodiscard]] static Patcher search_string(std::u16string_view text, bool null_terminated = false);

    /// Builds and applies a patch in one expression. The callback is invoked
    /// synchronously while the Patcher is alive, so it may safely capture
    /// variables from the code that is constructing the patch. It does not
    /// run inside the target function or expose that function's stack frame.
    template <typename Fn>
        requires std::invocable<Fn&, Patcher&>
    [[nodiscard]] static Result<Patch> apply(Fn&& fn);

    /// Builds and applies a patch, keeping all patched bytes and executable
    /// relay pages alive after the returned Patch is destroyed.
    template <typename Fn>
        requires std::invocable<Fn&, Patcher&>
    [[nodiscard]] static Result<Patch> apply_permanent(Fn&& fn);

    /// Restores the original bytes. Idempotent.
    Status restore();

    /// Makes this patch process-lifetime. Destruction no longer restores the
    /// target or releases relay/trampoline pages. `restore()` can still be
    /// called explicitly while the object is alive.
    Patch& make_permanent() noexcept;

    /// Alias for make_permanent(), useful when ownership is intentionally
    /// detached from a scope.
    Patch& detach() noexcept { return make_permanent(); }

    [[nodiscard]] bool permanent() const noexcept;

    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept { return active(); }

    [[nodiscard]] void* address() const noexcept;
    [[nodiscard]] std::span<const std::byte> original_bytes() const noexcept;
    [[nodiscard]] std::vector<WriteInfo> writes() const;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    friend class Patcher;
    explicit Patch(std::unique_ptr<detail::PatchState> state);

    std::unique_ptr<detail::PatchState> state_;
};

/// Fluent patch builder. A Patcher is a value-like, move-only recipe:
///
///     auto patch = Patch::search("48 8B 05 ?? ?? ?? ??")
///                      .offset(3)
///                      .jmp(&replacement)
///                      .apply();
///
/// The same object can build a signature and then write bytes:
///
///     auto patch = Patch::search()
///                      .jnz()
///                      .cmp(x64::r8d, 6)
///                      .offset(5)
///                      .write({0x07})
///                      .apply();
class IPATCH_API Patcher {
public:
    Patcher();
    ~Patcher();
    Patcher(Patcher&&) noexcept;
    Patcher& operator=(Patcher&&) noexcept;
    Patcher(const Patcher&) = delete;
    Patcher& operator=(const Patcher&) = delete;

    // ---------------------------------------------------------------- targets
    Patcher& in(Range range);
    Patcher& in(Module module);
    Patcher& in_main_module();
    Patcher& in_process(bool enabled = true);
    Patcher& executable_only(bool enabled = true);
    Patcher& alignment(std::size_t alignment);

    /// Requires the scan to produce exactly one match.
    ///
    /// Without this, search mode uses the earliest match. With it, a missing
    /// signature fails with `not_found` and an ambiguous signature fails with
    /// `ambiguous`, so a broad pattern cannot silently patch the wrong address.
    /// Call it before any write/build method resolves the signature.
    Patcher& unique(bool enabled = true);

    /// Adds a byte offset to the current cursor (or pending match before resolution).
    /// Repeated calls accumulate; arithmetic overflow is reported by apply().
    Patcher& offset(std::ptrdiff_t offset);

    /// Resolves the search, follows a disp32 target, then uses it as the cursor.
    /// Same offsets as MatchResult::rel32(). Call unique() before this method.
    Patcher& rel32(std::ptrdiff_t displacement_offset = 0,
                   std::ptrdiff_t next_instruction_offset = 4);
    Patcher& at(void* address);
    Patcher& seek(void* address) { return at(address); }

    // ------------------------------------------------------------ scan recipe
    Patcher& then(std::string_view signature,
                  std::size_t gap_min = Pattern::use_pending_gap,
                  std::size_t gap_max = Pattern::use_pending_gap);
    Patcher& then(Pattern pattern,
                  std::size_t gap_min = Pattern::use_pending_gap,
                  std::size_t gap_max = Pattern::use_pending_gap);
    Patcher& within(std::size_t gap_min, std::size_t gap_max);
    Patcher& within(std::size_t max_gap) { return within(0, max_gap); }

    /// Explicitly resolves the signature and moves the write cursor to it.
    Patcher& search_end();
    Patcher& end() { return search_end(); }

    // ------------------------------------------------------------- raw writes
    Patcher& write(std::span<const std::byte> bytes);
    Patcher& write(std::span<const std::uint8_t> bytes);
    Patcher& write(std::initializer_list<std::uint8_t> bytes);
    Patcher& write(std::initializer_list<std::byte> bytes);
    Patcher& bytes(std::span<const std::byte> data) { return write(data); }
    Patcher& bytes(std::initializer_list<std::uint8_t> data) { return write(data); }
    Patcher& fill(std::size_t count, std::uint8_t value = 0x90);

    /// Numeric overloads: sizeof(T) little-endian bytes on x86-64.
    /// write(0x10) writes sizeof(int); write({0x10}) writes one byte.
    /// Use explicit widths, e.g. expect<uint32_t>(0x2710).write<uint32_t>(10000).
    template <typename T> requires std::is_arithmetic_v<T>
    Patcher& write(T value) { return write_value(value); }

    template <typename T> requires std::is_arithmetic_v<T>
    Patcher& expect(T value) { return expect_value(value); }

    /// Replaces an unprefixed direct Jcc/JMP, preserving its target and span.
    /// Near Jcc -> JMP uses E9 rel32 + NOP; following addresses stay unchanged.
    /// Expansions that cannot fit fail with insufficient_space. A rel32 that
    /// cannot be adjusted fails with out_of_range. Advances by the old length.
    /// Original bytes are checked at apply() unless verify(false) is set.
    Patcher& replace_branch(x64::Branch branch);

    /// Writes an object's byte representation and advances by sizeof(T).
    /// Prefer fixed-width scalars; pointers write the address, not the pointee.
    template <typename T>
        requires (std::is_trivially_copyable_v<T> && !std::is_volatile_v<T>)
    Patcher& write_value(const T& value) {
        return write(std::as_bytes(std::span{&value, std::size_t{1}}));
    }

    template <typename T>
        requires (std::is_trivially_copyable_v<T> && !std::is_volatile_v<T>)
    Patcher& expect_value(const T& value) {
        return expect(std::as_bytes(std::span{&value, std::size_t{1}}));
    }

    /// Advances the write cursor without writing.
    Patcher& skip(std::ptrdiff_t count);

    /// Writes at an absolute address without disturbing the current cursor.
    Patcher& write_at(void* address, std::span<const std::byte> bytes);
    Patcher& write_at(void* address, std::initializer_list<std::uint8_t> bytes);

    /// Replaces `original_length` bytes at the cursor.
    ///
    /// If the replacement fits, it is written directly and padded with NOPs.
    /// If it is longer, the replacement is placed in a nearby code cave or
    /// relay page; the site gets a 2/5-byte jump to that springboard, which
    /// resumes at `cursor + original_length`. This preserves the instruction
    /// boundary instead of silently overwriting following instructions.
    Patcher& write_springboard(std::size_t original_length,
                               std::span<const std::byte> bytes);
    Patcher& write_springboard(std::size_t original_length,
                               std::span<const std::uint8_t> bytes);
    Patcher& write_springboard(std::size_t original_length,
                               std::initializer_list<std::uint8_t> bytes);
    Patcher& write_springboard(std::size_t original_length,
                               std::initializer_list<std::byte> bytes);

    /// Infers the original instruction length by decoding one instruction at
    /// the cursor. Use the explicit-length overload when replacing a range
    /// that contains more than one original instruction.
    Patcher& write_springboard(std::span<const std::byte> bytes);
    Patcher& write_springboard(std::span<const std::uint8_t> bytes);
    Patcher& write_springboard(std::initializer_list<std::uint8_t> bytes);
    Patcher& write_springboard(std::initializer_list<std::byte> bytes);

    using SpringboardBuilder = std::function<void(Patcher&)>;

    /// Builds an out-of-line springboard with the normal fluent instruction
    /// APIs instead of a pre-encoded byte vector.
    ///
    /// The callback receives a Patcher whose cursor is a newly allocated relay
    /// page. Everything emitted by the callback becomes the springboard; a jump
    /// back to `cursor + original_length` is appended automatically. The
    /// original bytes are not copied implicitly, so write the preserved
    /// instruction explicitly:
    ///
    ///     Patch::at(module, 0x1C483BC)
    ///         .springboard(7, [&](Patcher& p) {
    ///             p.test(x64::rsi, x64::rsi)
    ///              .jz(module.at(0x1C47EA2))
    ///              .mov(x64::rcx, x64::mem(x64::rbx, 0x1D8));
    ///         })
    ///         .apply();
    ///
    /// The body must write a contiguous instruction stream with cursor-based
    /// methods. It must not call apply(), use nested springboards/relays, or
    /// emit expect() checks. The site must have at least five readable bytes;
    /// otherwise `insufficient_space` is reported.
    Patcher& springboard(std::size_t original_length, SpringboardBuilder body);

    /// Infers the original instruction length by decoding one instruction at
    /// the cursor, then builds the springboard with `springboard(length, body)`.
    Patcher& springboard(SpringboardBuilder body);

    /// Guards the single instruction at the cursor against a null register.
    ///
    ///     auto patch = Patch::at(module, 0x1C483BC)
    ///                      .guard_null(x64::rsi, module.at(0x1C47EA2))
    ///                      .apply();
    ///
    /// This is the one-call shortcut for the common `test/jz` springboard; use
    /// `springboard()` when the replacement needs more instructions or a custom
    /// sequence. The original instruction is decoded and preserved in an
    /// automatically generated springboard. If `reg` is zero the stub jumps to
    /// `if_null`; otherwise it executes the original instruction and resumes at
    /// `cursor + instruction_length`.
    ///
    /// The register must be 64-bit and non-wildcard. The original instruction
    /// must be position-independent: RIP-relative operands and relative
    /// control-flow instructions are rejected with `unsupported_instruction`.
    /// The inserted `test` clobbers flags.
    Patcher& guard_null(x64::Reg reg, void* if_null);

    /// Verifies the bytes at the write cursor before applying.
    ///
    /// For raw writes the expected size must match the write size. For
    /// `write_springboard` / `springboard` / `guard_null` it must match the
    /// original range.
    Patcher& expect(std::span<const std::byte> bytes);
    Patcher& expect(std::initializer_list<std::uint8_t> bytes);

    Patcher& verify(bool enabled = true);
    Patcher& freeze_threads(bool enabled = true);

    /// Runs a register-level callback at the current patch point, then
    /// continues with the instruction that was replaced by the runtime
    /// springboard. The callback can inspect or modify CpuContext::rsp-based
    /// locals and all captured registers.
    /// For example: ctx.local<int>(x64::rbp - 0x20) = 42;
    /// ctx.set(x64::xmm3, ctx.get<float>(x64::xmm3) * 2.0f);
    ///
    /// The cursor must point to a complete, position-independent instruction;
    /// RIP-relative and relative-control-flow instructions are rejected.
    /// Runtime callbacks must not throw.
    Patcher& runtime(RuntimeCallback callback);

    /// Installs a runtime callback object. The callable is kept alive by the
    /// resulting Patch, so captures can safely refer to state for as long as
    /// the patch remains active. The callable must be noexcept because it is
    /// entered from generated machine code.
    template <typename Callable>
        requires std::is_nothrow_invocable_v<std::remove_reference_t<Callable>&,
                                             CpuContext&>
    Patcher& runtime(Callable&& callback);

    // --------------------------------------------------------------- jumps
    /// Auto-encodes E9 rel32 when reachable, otherwise FF 25 + absolute target.
    /// With a null target, scan mode emits the wildcard short-jump signature.
    Patcher& jmp(void* target = nullptr);
    Patcher& jmp_short(void* target);
    Patcher& jmp_abs(void* target);
    Patcher& call(void* target = nullptr);
    Patcher& ret();
    Patcher& int3();
    Patcher& nop(std::size_t count = 1);
    Patcher& push(x64::Reg reg);
    Patcher& pop(x64::Reg reg);

    // ---------------------------------------------------------- instructions
    Patcher& mov(x64::Reg dst, x64::Reg src);
    Patcher& mov(x64::Reg dst, std::int64_t imm);
    Patcher& mov(x64::Reg dst, x64::Mem src);
    Patcher& mov(x64::Mem dst, x64::Reg src);
    Patcher& mov(x64::Mem dst, std::int32_t imm);
    Patcher& lea(x64::Reg dst, x64::Mem src);

    Patcher& add(x64::Reg dst, x64::Reg src);
    Patcher& add(x64::Reg dst, std::int32_t imm);
    Patcher& sub(x64::Reg dst, x64::Reg src);
    Patcher& sub(x64::Reg dst, std::int32_t imm);
    Patcher& and_(x64::Reg dst, x64::Reg src);
    Patcher& and_(x64::Reg dst, std::int32_t imm);
    Patcher& or_(x64::Reg dst, x64::Reg src);
    Patcher& or_(x64::Reg dst, std::int32_t imm);
    Patcher& xor_(x64::Reg dst, x64::Reg src);
    Patcher& xor_(x64::Reg dst, std::int32_t imm);
    Patcher& cmp(x64::Reg dst, x64::Reg src);
    Patcher& cmp(x64::Reg dst, std::int32_t imm);
    Patcher& test(x64::Reg dst, x64::Reg src);
    Patcher& test(x64::Reg dst, std::int32_t imm);
    Patcher& inc(x64::Reg dst);
    Patcher& dec(x64::Reg dst);

    // Conditional jumps. Null target = wildcard displacement in scan mode.
    Patcher& je(void* target = nullptr);
    Patcher& jne(void* target = nullptr);
    Patcher& jz(void* target = nullptr) { return je(target); }
    Patcher& jnz(void* target = nullptr) { return jne(target); }
    Patcher& jg(void* target = nullptr);
    Patcher& jge(void* target = nullptr);
    Patcher& jl(void* target = nullptr);
    Patcher& jle(void* target = nullptr);
    Patcher& ja(void* target = nullptr);
    Patcher& jae(void* target = nullptr);
    Patcher& jb(void* target = nullptr);
    Patcher& jbe(void* target = nullptr);
    Patcher& js(void* target = nullptr);
    Patcher& jns(void* target = nullptr);

    // --------------------------------------------------------------- commit
    /// Resolves the signature, applies all writes, and returns an RAII handle.
    [[nodiscard]] Result<Patch> apply();

    /// Resolves the signature, applies all writes, and returns a process-
    /// lifetime patch. Relay pages are retained until process exit.
    [[nodiscard]] Result<Patch> apply_permanent();

    /// Resolves the signature and returns its base (before offset/writes).
    /// After rel32(), the resolved target becomes the base.
    [[nodiscard]] MatchResult find();
    [[nodiscard]] Result<Match> require_find();

    /// Resolves without applying writes and returns the current write cursor,
    /// including offset(), skip(), rel32() and bytes already planned.
    [[nodiscard]] MatchResult cursor();

    /// Access current memory at the cursor, without advancing or applying writes.
    /// Planned writes are not visible until apply(). See MatchResult for lifetime
    /// and alignment requirements; writes through ptr/ref are not restored.
    template <typename T> requires requires(MatchResult m) { m.read<T>(); }
    [[nodiscard]] Result<T> read() { return cursor().read<T>(); }

    template <typename T> requires requires(MatchResult m) { m.ptr<T>(); }
    [[nodiscard]] Result<T*> ptr() { return cursor().ptr<T>(); }

    template <typename T> requires requires(MatchResult m) { m.ref<T>(); }
    [[nodiscard]] Result<std::reference_wrapper<T>> ref() { return cursor().ref<T>(); }

    [[nodiscard]] const Error& last_error() const noexcept;
    [[nodiscard]] bool ok() const noexcept;

private:
    friend class Patch;
    Patcher& runtime_callable(RuntimeInvoker invoker, void* context,
                              std::shared_ptr<void> owner);
    std::unique_ptr<detail::PlanState> state_;
};

using PatchBuilder = Patcher;

template <typename Fn>
    requires std::invocable<Fn&, Patcher&>
[[nodiscard]] inline Result<Patch> Patch::apply(Fn&& fn) {
    Patcher patcher;
    std::invoke(std::forward<Fn>(fn), patcher);
    return patcher.apply();
}

template <typename Fn>
    requires std::invocable<Fn&, Patcher&>
[[nodiscard]] inline Result<Patch> Patch::apply_permanent(Fn&& fn) {
    Patcher patcher;
    std::invoke(std::forward<Fn>(fn), patcher);
    return patcher.apply_permanent();
}

template <typename Callable>
    requires std::is_nothrow_invocable_v<std::remove_reference_t<Callable>&,
                                         CpuContext&>
inline Patcher& Patcher::runtime(Callable&& callback) {
    using callable_type = std::decay_t<Callable>;
    if constexpr (std::is_pointer_v<callable_type>) {
        if (!callback) return runtime(static_cast<RuntimeCallback>(nullptr));
    }
    using holder_type = detail::RuntimeCallableHolder<callable_type>;
    auto holder = std::make_shared<holder_type>(holder_type{
        std::forward<Callable>(callback)});
    auto* context = holder.get();
    return runtime_callable(&detail::invoke_runtime_callable<callable_type>, context,
                            std::move(holder));
}

} // namespace ipatch
