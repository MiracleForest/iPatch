// SPDX-License-Identifier: MIT
// Demonstrates alternatives, multi-condition chains, and match diagnostics.
#include <ipatch/ipatch.hpp>

#include <cstdint>
#include <print>

int main() {
    static std::uint8_t sample[] = {
        0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, // mov rax, [rip+...]
        0x48, 0x85, 0xC0,                         // test rax, rax
        0x74, 0x10,                               // je +0x10
        0xE8, 0xAA, 0xBB, 0xCC, 0xDD,             // call ...
    };
    const auto range = ipatch::Range::from(sample, sizeof(sample));

    auto query = ipatch::scan({
        "48 8B 05 ?? ?? ?? ??",
        "48 89 5C 24 ??",
    });
    query.in(range).limit(10);

    auto matches = query.all();
    if (!matches) {
        std::println("scan failed: {}", matches.error().format());
        return 1;
    }
    std::println("found {} alternative match(es)", matches->size());
    for (const auto& match : *matches) {
        std::println("  {} pattern={}", static_cast<void*>(match.address),
                     match.pattern_index);
    }

    // Two independent conditions, with a bounded gap between them.
    auto chain = ipatch::Pattern::parse("48 8B 05 ?? ?? ?? ??");
    if (!chain) return 1;
    chain->within(0, 32).then("E8 ?? ?? ?? ??");

    if (auto* address = chain->find_first(range).value_or(nullptr)) {
        std::println("multi-condition match at {}", static_cast<void*>(address));
    } else {
        std::println("multi-condition pattern not found");
    }

    // Scan the main module for a common compiler prologue.
    auto module_matches = ipatch::scan({"48 89 5C 24 ??", "48 83 EC ??"})
                              .in_main_module()
                              .limit(5)
                              .all();
    if (module_matches) {
        std::println("main module sample matches: {}", module_matches->size());
        for (const auto& match : *module_matches) {
            std::println("  {}", static_cast<void*>(match.address));
        }
    }
    return 0;
}
