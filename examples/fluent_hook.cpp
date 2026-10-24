// SPDX-License-Identifier: MIT
// Shows the monadic signature style from the original design conversation and
// the instruction-level fluent pattern builder.
#include <ipatch/ipatch.hpp>

#include <cstdint>
#include <optional>
#include <print>

namespace {

std::byte* find_gamemode_flag() {
    // 75 06           jnz +6
    // 41 83 F8 06     cmp r8d, 6
    static std::uint8_t sample[] = {0x90, 0x75, 0x06, 0x41, 0x83, 0xF8, 0x06, 0xC3};
    const ipatch::Range range{reinterpret_cast<std::byte*>(sample),
                              reinterpret_cast<std::byte*>(sample) + sizeof(sample)};

    return ipatch::scan("75 06 41 83 F8 06")
        .in(range)
        .first()
        .or_else([]() {
            std::println("signature was not found");
            return std::optional<std::byte*>{};
        })
        .transform([](std::byte* ptr) { return ptr + 5; })
        .value();
}

} // namespace

int main() {
    if (auto* flag = find_gamemode_flag()) {
        std::println("immediate is at {} (value {})", static_cast<void*>(flag),
                     static_cast<unsigned>(*flag));
    }

    // The same location, built from instructions instead of raw bytes:
    //   .jnz()              -> 75 ??
    //   .cmp(r8d, 6)        -> 41 83 F8 06
    //   .offset(5)          -> the immediate byte
    //   .write({0x07})      -> cmp r8d, 7
    static std::uint8_t sample[] = {0x75, 0x06, 0x41, 0x83, 0xF8, 0x06};
    const auto range = ipatch::Range::from(sample, sizeof(sample));

    auto patch = ipatch::Patch::search()
                     .jnz()
                     .cmp(ipatch::x64::r8d, 6)
                     .in(range)
                     .offset(5)
                     .write({0x07})
                     .apply();
    if (!patch) {
        std::println("instruction patch failed: {}", patch.error().format());
        return 1;
    }

    std::println("patched immediate: {}", static_cast<unsigned>(sample[5]));
    auto restored = patch->restore();
    if (!restored) {
        std::println("restore failed: {}", restored.error().format());
        return 1;
    }
    std::println("restored immediate: {}", static_cast<unsigned>(sample[5]));
    return 0;
}
