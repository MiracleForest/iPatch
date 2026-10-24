// SPDX-License-Identifier: MIT
// The smallest useful iPatch example: replace a function entry with a jump,
// keep the returned RAII handle, and restore when it goes out of scope.
#include <ipatch/ipatch.hpp>

#include <print>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) && !defined(__clang__)
#define NOINLINE __attribute__((noinline, noipa))
#else
#define NOINLINE __attribute__((noinline))
#endif

NOINLINE int original(int value) {
    return value * 2;
}

NOINLINE int replacement(int value) {
    return value + 100;
}

template <typename Fn, typename... Args>
auto call_volatile(Fn fn, Args... args) {
    Fn volatile target = fn;
    return target(args...);
}

int main() {
    std::println("before: {}", call_volatile(&original, 21));

    auto patch = ipatch::Patch::at(reinterpret_cast<void*>(&original))
                     .jmp(reinterpret_cast<void*>(&replacement))
                     .apply();
    if (!patch) {
        std::println("patch failed: {}", patch.error().format());
        return 1;
    }

    std::println("after:  {}", call_volatile(&original, 21));
    auto restored = patch->restore();
    if (!restored) {
        std::println("restore failed: {}", restored.error().format());
        return 1;
    }
    std::println("restored: {}", call_volatile(&original, 21));
    return 0;
}
