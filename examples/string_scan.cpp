// SPDX-License-Identifier: MIT
#include <ipatch/ipatch.hpp>

#include <array>
#include <cstring>
#include <print>

int main() {
    using namespace ipatch;
    // A small in-memory fixture: LEA RCX,[RIP+25] refers to text at byte 32.
    // These instruction bytes are scanned, never executed.
    static std::array<std::uint8_t, 64> sample{0x48, 0x8D, 0x0D, 25, 0, 0, 0};
    std::memcpy(sample.data() + 32, "mode=0", 7);
    const auto range = Range::from(sample.data(), sample.size());

    auto text = scan_string("mode=0", true).in(range).unique();
    auto referenced = scan("48 8D 0D ?? ?? ?? ??").in(range).unique().rel32(3, 7);
    if (!text || !referenced) {
        std::println("locate failed: {}", (!text ? text.error() : referenced.error()).format());
        return 1;
    }
    if (text.address() != referenced.address()) return 1;

    auto rva = text.rva(Module::main());
    if (!rva) {
        std::println("RVA failed: {}", rva.error().format());
        return 1;
    }
    std::println("text at RVA {:#x}; LEA resolves to the same address", *rva);

    // Reuse the resolved address and keep lookup errors intact. Typed reads
    // and writes avoid spelling characters/floats/integers as machine bytes.
    auto setting = text.offset(5);
    auto old_value = setting.read<char>();
    if (!old_value) return 1;
    auto patch = Patch::at(setting).expect_value(*old_value).write_value('1').apply();
    if (!patch) {
        std::println("patch failed: {}", patch.error().format());
        return 1;
    }
    std::println("patched text: {}", reinterpret_cast<const char*>(sample.data() + 32));
    auto restored = patch->restore();
    if (!restored) return 1;
    std::println("restored text: {}", reinterpret_cast<const char*>(sample.data() + 32));
    return 0;
}
