// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <type_traits>

#include "ipatch/config.hpp"
#include "ipatch/x64.hpp"

namespace ipatch {

/// Values copied to/from captured machine state, without type punning.
template <typename T>
concept ContextValue = std::is_trivially_copyable_v<T> &&
    !std::is_const_v<T> && !std::is_volatile_v<T> && !std::is_array_v<T>;

namespace detail {
template <ContextValue T>
[[nodiscard]] T context_load(const void* address) noexcept {
    std::array<std::byte, sizeof(T)> bytes;
    std::memcpy(bytes.data(), address, bytes.size());
    return std::bit_cast<T>(bytes);
}

// Invalid selectors are programming errors. Callbacks are noexcept, so fail
// closed even in release builds instead of indexing another register/slot.
inline void context_require(bool condition) noexcept {
    if (!condition) std::terminate();
}
} // namespace detail

/// Register and stack state captured at a runtime patch point.
///
/// `rsp` points to the stack as it was before the injected callback call and
/// `rip` is the instruction that resumes after the runtime patch. A callback
/// may change registers, flags, stack memory, `rsp`, or `rip`; the thunk
/// restores the resulting state and resumes from the selected address.
struct alignas(16) CpuContext {
    std::uint64_t rax{0};
    std::uint64_t rcx{0};
    std::uint64_t rdx{0};
    std::uint64_t rbx{0};
    std::uint64_t rsp{0};
    std::uint64_t rbp{0};
    std::uint64_t rsi{0};
    std::uint64_t rdi{0};
    std::uint64_t r8{0};
    std::uint64_t r9{0};
    std::uint64_t r10{0};
    std::uint64_t r11{0};
    std::uint64_t r12{0};
    std::uint64_t r13{0};
    std::uint64_t r14{0};
    std::uint64_t r15{0};
    std::uint64_t rip{0};
    std::uint64_t rflags{0};
    std::array<std::array<std::byte, 16>, 16> xmm{};

    /// Typed lane access: get<float>(xmm3), get<float, 2>(xmm3).
    /// Lane is in units of T. Writes preserve every byte outside that lane.
    template <ContextValue T, std::size_t Lane = 0, unsigned Index>
        requires (sizeof(T) <= 16 && Lane < 16 / sizeof(T))
    [[nodiscard]] T get(x64::XmmReg<Index>) const noexcept {
        return detail::context_load<T>(xmm[Index].data() + Lane * sizeof(T));
    }

    template <ContextValue T, std::size_t Lane = 0, unsigned Index>
        requires (sizeof(T) <= 16 && Lane < 16 / sizeof(T))
    void set(x64::XmmReg<Index>, const T& value) noexcept {
        const auto bytes = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
        std::memcpy(xmm[Index].data() + Lane * sizeof(T), bytes.data(), bytes.size());
    }

    /// Bitwise GPR access. sizeof(T) must match the named register width.
    template <ContextValue T>
        requires (sizeof(T) <= 8)
    [[nodiscard]] T get(x64::Reg reg) const noexcept {
        detail::context_require(sizeof(T) == reg.size);
        return detail::context_load<T>(&register_value(reg));
    }

    /// EAX/r8d/etc writes zero-extend; AX/AL/etc preserve the upper bits.
    template <ContextValue T>
        requires (sizeof(T) <= 8)
    void set(x64::Reg reg, const T& value) noexcept {
        detail::context_require(sizeof(T) == reg.size);
        auto& destination = const_cast<std::uint64_t&>(register_value(reg));
        // Copy first so a value aliasing destination remains valid.
        std::uint64_t bits{};
        std::memcpy(&bits, &value, sizeof(T));
        if constexpr (sizeof(T) == 4 || sizeof(T) == 8) destination = bits;
        else std::memcpy(&destination, &bits, sizeof(T));
    }

    /// Reads/writes [base + disp], including unaligned stack slots and fields.
    /// The caller owns memory validity; no object reference is type-punned.
    template <ContextValue T>
    [[nodiscard]] T get(x64::Mem operand) const noexcept {
        return detail::context_load<T>(memory_address(operand, sizeof(T)));
    }

    template <ContextValue T>
    void set(x64::Mem operand, const T& value) noexcept {
        const auto bytes = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
        std::memcpy(memory_address(operand, sizeof(T)), bytes.data(), bytes.size());
    }

    /// Typed references for actual aligned objects: local<int>(rbp - 0x20).
    /// For unaligned storage, use get<T>(operand) / set(operand, value).
    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T& local(x64::Mem operand) noexcept {
        return *reinterpret_cast<T*>(memory_address(operand, sizeof(T)));
    }

    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T& local(x64::Mem operand) const noexcept {
        return *reinterpret_cast<const T*>(memory_address(operand, sizeof(T)));
    }

    /// A captured pointer directly selected by register name: as<Object>(rbx).
    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T* as(x64::Reg reg) noexcept {
        detail::context_require(reg.size == 8);
        return as<T>(register_value(reg));
    }

    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T* as(x64::Reg reg) const noexcept {
        detail::context_require(reg.size == 8);
        return as<T>(register_value(reg));
    }

    /// Converts a captured pointer-sized register or address to a typed
    /// pointer. This is intentionally just an address conversion; it does not
    /// validate the pointee.
    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T* as(std::uintptr_t address) noexcept {
        return reinterpret_cast<T*>(address);
    }

    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T* as(std::uintptr_t address) const noexcept {
        return reinterpret_cast<const T*>(address);
    }

    /// Returns a typed pointer relative to the target's pre-callback RSP.
    /// The caller must provide an offset confirmed from the target's machine
    /// code; the compiler may move or eliminate a C++ local variable.
    template <typename T>
    [[nodiscard]] T* stack_at(std::ptrdiff_t offset) noexcept {
        return reinterpret_cast<T*>(reinterpret_cast<std::byte*>(rsp) + offset);
    }

    template <typename T>
    [[nodiscard]] const T* stack_at(std::ptrdiff_t offset) const noexcept {
        return reinterpret_cast<const T*>(reinterpret_cast<const std::byte*>(rsp) + offset);
    }

    /// Compile-time offset form for callbacks that use a fixed stack slot.
    ///
    ///     context.stack_at<0x20, std::uint32_t>()
    ///
    /// The offset is relative to the target's original RSP, before the
    /// runtime thunk called the callback.
    template <std::ptrdiff_t Offset, typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T* stack_at() noexcept {
        return stack_at<T>(Offset);
    }

    template <std::ptrdiff_t Offset, typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T* stack_at() const noexcept {
        return stack_at<T>(Offset);
    }

    template <typename T, std::ptrdiff_t Offset>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T* stack_at() noexcept {
        return stack_at<Offset, T>();
    }

    template <typename T, std::ptrdiff_t Offset>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T* stack_at() const noexcept {
        return stack_at<Offset, T>();
    }

    template <typename T>
    [[nodiscard]] T& local(std::ptrdiff_t offset) noexcept {
        return *stack_at<T>(offset);
    }

    template <typename T>
    [[nodiscard]] const T& local(std::ptrdiff_t offset) const noexcept {
        return *stack_at<T>(offset);
    }

    /// Compile-time offset form of local<T>(offset).
    template <std::ptrdiff_t Offset, typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T& local() noexcept {
        return *stack_at<Offset, T>();
    }

    template <std::ptrdiff_t Offset, typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T& local() const noexcept {
        return *stack_at<Offset, T>();
    }

    template <typename T, std::ptrdiff_t Offset>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T& local() noexcept {
        return local<Offset, T>();
    }

    template <typename T, std::ptrdiff_t Offset>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T& local() const noexcept {
        return local<Offset, T>();
    }

    /// Short alias for stack_at<T>(offset), useful when the callback treats
    /// the slot as a field selected by an offset.
    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T& offset(std::ptrdiff_t value) noexcept {
        return *stack_at<T>(value);
    }

    template <typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T& offset(std::ptrdiff_t value) const noexcept {
        return *stack_at<T>(value);
    }

    template <std::ptrdiff_t Offset, typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T& offset() noexcept {
        return local<Offset, T>();
    }

    template <std::ptrdiff_t Offset, typename T>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T& offset() const noexcept {
        return local<Offset, T>();
    }

    template <typename T, std::ptrdiff_t Offset>
        requires (!std::is_void_v<T>)
    [[nodiscard]] T& offset() noexcept {
        return local<Offset, T>();
    }

    template <typename T, std::ptrdiff_t Offset>
        requires (!std::is_void_v<T>)
    [[nodiscard]] const T& offset() const noexcept {
        return local<Offset, T>();
    }

private:
    [[nodiscard]] const std::uint64_t& register_value(x64::Reg reg) const noexcept {
        detail::context_require(reg.valid() && !reg.wildcard && reg.id < 16);
        // Members are intentionally mapped by name, never assumed to be an array.
        switch (reg.id) {
        case 0: return rax; case 1: return rcx; case 2: return rdx; case 3: return rbx;
        case 4: return rsp; case 5: return rbp; case 6: return rsi; case 7: return rdi;
        case 8: return r8; case 9: return r9; case 10: return r10; case 11: return r11;
        case 12: return r12; case 13: return r13; case 14: return r14; case 15: return r15;
        default: std::terminate();
        }
    }

    [[nodiscard]] void* memory_address(x64::Mem operand, std::size_t width) const noexcept {
        detail::context_require(operand.base.size == 8 && !operand.wildcard_base &&
            !operand.wildcard_disp && (operand.size == 0 || operand.size == width));
        const auto base = register_value(operand.base);
        const auto displacement = static_cast<std::int64_t>(operand.disp);
        const auto address = base + static_cast<std::uint64_t>(displacement);
        detail::context_require(base != 0 && address != 0 &&
            (displacement < 0 ? address < base : address >= base) &&
            width - 1 <= UINT64_MAX - address);
        return reinterpret_cast<void*>(address);
    }
};

/// Runtime callback invoked by Patcher::runtime(). The callback must not
/// throw across the generated machine-code thunk.
using RuntimeCallback = void (*)(CpuContext&) noexcept;
using RuntimeInvoker = void (*)(void*, CpuContext&) noexcept;

namespace detail {

template <typename Callable>
struct RuntimeCallableHolder {
    Callable callable;
};

template <typename Callable>
void invoke_runtime_callable(void* value, CpuContext& context) noexcept {
    auto* holder = static_cast<RuntimeCallableHolder<Callable>*>(value);
    std::invoke(holder->callable, context);
}

} // namespace detail

static_assert(offsetof(CpuContext, xmm) % 16 == 0);
static_assert(std::is_standard_layout_v<CpuContext>);
static_assert(std::is_trivially_copyable_v<CpuContext>);

} // namespace ipatch
