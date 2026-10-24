// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <concepts>
#include <functional>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>

#include "ipatch/config.hpp"
#include "ipatch/error.hpp"
#include "ipatch/pattern.hpp"
#include "ipatch/range.hpp"
#include "ipatch/scan.hpp"

namespace ipatch {

struct HookOptions {
    /// Suspend every other thread while the entry bytes are swapped.
    bool freeze_threads{true};

    /// Verify that the original bytes still match before installing.
    bool verify{true};

    /// Always route through a near relay page, even when a direct rel32 jump
    /// would reach the detour. Useful for testing the relay path.
    bool force_relay{false};

    /// If a direct 5-byte jump is impossible, try a 2-byte short jump to a
    /// nearby padding cave. This is best-effort and only uses 0xCC/0x90/0x00
    /// padding runs.
    bool allow_short_springboard{true};

    /// 0 = choose automatically (normally 5 bytes for a rel32 jump).
    std::size_t steal_bytes{0};

    /// Optional hint for trampoline placement; the allocator still guarantees
    /// that the result is within +/-2 GiB when possible.
    void* trampoline_hint{nullptr};
};

namespace detail {
struct HookState;

IPATCH_API void* get_active_hook_context() noexcept;
IPATCH_API void clear_active_hook_context() noexcept;

template <typename Signature>
struct hook_signature {
    template <typename Callable>
    static constexpr bool invocable = false;
};

template <typename Return, typename... Args>
struct hook_signature<Return(Args...)> {
    using return_type = Return;
    template <typename Callable>
    static constexpr bool invocable = std::is_invocable_r_v<Return, Callable&, Args...>;
};

template <typename Return, typename... Args>
struct hook_signature<Return(Args...) noexcept> {
    using return_type = Return;
    template <typename Callable>
    static constexpr bool invocable = std::is_nothrow_invocable_r_v<Return, Callable&, Args...>;
};

template <typename Callable>
struct HookCallableContext {
    Callable callable;
};

template <typename Signature, typename Callable>
struct HookCallableAdapter;

template <typename Return, typename... Args, typename Callable>
struct HookCallableAdapter<Return(Args...), Callable> {
    static Return invoke(Args... args) {
        auto* context = static_cast<HookCallableContext<Callable>*>(get_active_hook_context());
        clear_active_hook_context();
        if constexpr (std::is_void_v<Return>) {
            std::invoke(context->callable, std::forward<Args>(args)...);
        } else {
            return std::invoke(context->callable, std::forward<Args>(args)...);
        }
    }
};

template <typename Return, typename... Args, typename Callable>
struct HookCallableAdapter<Return(Args...) noexcept, Callable>
{
    static Return invoke(Args... args) noexcept {
        return HookCallableAdapter<Return(Args...), Callable>::invoke(std::forward<Args>(args)...);
    }
};
} // namespace detail

/// An inline hook with automatic trampoline and relay generation.
///
///     auto hook = Hook::create(&target, &detour);
///     if (hook) {
///         auto original = hook->original<int(*)(int)>();
///         assert(target(1) == 101);
///         assert(original(1) == 2);
///     }
///
/// If the detour is farther than +/-2 GiB, the target receives a rel32 jump to
/// a nearby relay page, and the relay performs the absolute jump. The stolen
/// instructions are relocated into a trampoline next to the relay.
class IPATCH_API Hook {
public:
    Hook();
    ~Hook();

    Hook(const Hook&) = delete;
    Hook& operator=(const Hook&) = delete;
    Hook(Hook&& other) noexcept;
    Hook& operator=(Hook&& other) noexcept;

    [[nodiscard]] static Result<Hook> create(void* target, void* detour,
                                             HookOptions options = {});

    /// Infers the ABI from a typed target. Native matching pointers take the
    /// direct path; captures and return conversions use the callable adapter.
    template <typename Signature, typename Callable>
        requires (std::is_function_v<Signature> &&
                  detail::hook_signature<Signature>::template invocable<std::decay_t<Callable>>)
    [[nodiscard]] static Result<Hook> create(Signature* target, Callable&& callback,
                                            HookOptions options = {}) {
        if constexpr (std::is_convertible_v<Callable, Signature*>) {
            auto* detour = static_cast<Signature*>(std::forward<Callable>(callback));
            return create(reinterpret_cast<void*>(target), reinterpret_cast<void*>(detour), options);
        } else {
            return create_typed<Signature>(reinterpret_cast<void*>(target),
                                            std::forward<Callable>(callback), options);
        }
    }

    /// Accepts a captureless lambda directly. The lambda is converted to its
    /// native function pointer, so it has the
    /// exact same ABI requirements as the void* overload.
    ///
    /// Capturing callables use create_typed() below; the plain overload keeps
    /// the native function-pointer ABI and therefore does not add context.
    template <typename Callable>
        requires (!std::is_pointer_v<std::remove_cvref_t<Callable>> &&
                  std::is_empty_v<std::remove_cvref_t<Callable>> &&
                  requires(std::remove_cvref_t<Callable>& callable) { +callable; })
    [[nodiscard]] static Result<Hook> create(void* target, Callable&& callback,
                                             HookOptions options = {}) {
        using callback_type = std::remove_cvref_t<Callable>;
        using function_type = decltype(+std::declval<callback_type&>());
        const auto function = static_cast<function_type>(std::forward<Callable>(callback));
        return create(target, reinterpret_cast<void*>(function), options);
    }

    /// Installs a capturing callable when the target signature is known.
    /// `Signature` must be written as `Return(Args...)`, for example:
    ///
    ///     auto hook = Hook::create_typed<int(int)>(target, [bias](int value) {
    ///         return value + bias;
    ///     });
    ///
    /// The generated thunk preserves the Windows x64 volatile argument
    /// registers and XMM0-XMM3 while entering the type-erased callback. This
    /// API still requires the declared signature to match the target ABI.
    template <typename Signature, typename Callable>
        requires detail::hook_signature<std::remove_pointer_t<Signature>>::template invocable<
            std::remove_cvref_t<Callable>>
    [[nodiscard]] static Result<Hook> create_typed(void* target, Callable&& callback,
                                                    HookOptions options = {});

    /// A scanned address has no C++ signature: supply it explicitly while
    /// preserving any failed lookup before constructing the callback holder.
    template <typename Signature, typename Callable>
        requires detail::hook_signature<std::remove_pointer_t<Signature>>::template invocable<
            std::remove_cvref_t<Callable>>
    [[nodiscard]] static Result<Hook> create_typed(const MatchResult& target, Callable&& callback,
                                                 HookOptions options = {}) {
        if (!target) return std::unexpected(target.error());
        return create_typed<Signature>(target.address(), std::forward<Callable>(callback), options);
    }

    template <typename Signature, typename Callable>
        requires detail::hook_signature<std::remove_pointer_t<Signature>>::template invocable<
            std::remove_cvref_t<Callable>>
    [[nodiscard]] static Result<Hook> create_typed(const Result<std::byte*>& target, Callable&& callback,
                                                 HookOptions options = {}) {
        return create_typed<Signature>(MatchResult(target), std::forward<Callable>(callback), options);
    }

    /// Scans the main module for the first signature match and hooks it.
    [[nodiscard]] static Result<Hook> create(std::string_view signature, void* detour,
                                             HookOptions options = {});

    [[nodiscard]] static Result<Hook> create(Pattern pattern, void* detour,
                                             HookOptions options = {});

    [[nodiscard]] static Result<Hook> create(Pattern pattern, Range range, void* detour,
                                             HookOptions options = {});

    /// Restores the original entry bytes. The trampoline allocation is kept
    /// alive until the Hook is destroyed so in-flight original() calls remain
    /// valid. Idempotent.
    Status remove();

    [[nodiscard]] bool installed() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept { return installed(); }

    [[nodiscard]] void* target() const noexcept;
    [[nodiscard]] void* detour() const noexcept;
    [[nodiscard]] void* original() const noexcept;
    [[nodiscard]] void* trampoline() const noexcept;
    [[nodiscard]] void* relay() const noexcept;

    template <typename T>
    [[nodiscard]] T original() const noexcept {
        return reinterpret_cast<T>(original());
    }

    [[nodiscard]] std::size_t stolen_bytes() const noexcept;
    [[nodiscard]] std::size_t patch_bytes() const noexcept;
    [[nodiscard]] bool uses_relay() const noexcept;

private:
    using CallbackDestroy = void (*)(void*) noexcept;

    [[nodiscard]] static Result<Hook> create_callable(void* target, void* context,
                                                       void* adapter,
                                                       CallbackDestroy destroy,
                                                       HookOptions options);

    explicit Hook(std::unique_ptr<detail::HookState> state);
    std::unique_ptr<detail::HookState> state_;
};

} // namespace ipatch

namespace ipatch {

template <typename Signature, typename Callable>
    requires detail::hook_signature<std::remove_pointer_t<Signature>>::template invocable<
        std::remove_cvref_t<Callable>>
[[nodiscard]] inline Result<Hook> Hook::create_typed(void* target, Callable&& callback,
                                                      HookOptions options) {
    using signature = std::remove_pointer_t<Signature>;
    using callable_type = std::decay_t<Callable>;
    using context_type = detail::HookCallableContext<callable_type>;
    if constexpr (std::is_pointer_v<callable_type>) {
        if (!callback) return fail(ErrorCode::invalid_argument, "hook callback is null");
    }
    auto context = std::make_unique<context_type>(context_type{std::forward<Callable>(callback)});
    auto* adapter = &detail::HookCallableAdapter<signature, callable_type>::invoke;
    const auto destroy = [](void* value) noexcept {
        delete static_cast<context_type*>(value);
    };
    auto result = create_callable(target, context.get(), reinterpret_cast<void*>(adapter), destroy,
                                  options);
    if (result) context.release();
    return result;
}

} // namespace ipatch
