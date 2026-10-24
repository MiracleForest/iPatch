// SPDX-License-Identifier: MIT
#include <ipatch/ipatch.hpp>
#include <cstring>
#include <print>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

struct Settings { int replacement; float scale; };

int main() {
    using namespace ipatch;
    using namespace ipatch::x64;
    struct Page {
        void* data = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        ~Page() { if (data) VirtualFree(data, 0, MEM_RELEASE); }
    } page;
    if (!page.data) return 1;

    // Test function int(Settings* in RCX, float in XMM1): local at [RBP-4],
    // float copied to XMM3. Return local + int(XMM3). NOPs mark the patch site.
    const std::uint8_t code[] = {
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0xC7, 0x45, 0xFC, 7, 0, 0, 0, 0x0F, 0x28, 0xD9,
        0x90, 0x90, 0x90, 0x90, 0x90,
        0xF3, 0x0F, 0x2C, 0xC3, 0x03, 0x45, 0xFC,
        0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3,
    };
    std::memcpy(page.data, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), page.data, sizeof(code));
    auto function = reinterpret_cast<int (*)(Settings*, float)>(page.data);
    Settings settings{42, 3.0f};
    const auto before = function(&settings, 2.0f);

    auto patch = Patch::at(static_cast<std::byte*>(page.data) + 18)
        .runtime([](CpuContext& ctx) noexcept {
            const auto* settings = ctx.as<Settings>(rcx);
            ctx.local<int>(rbp - 4) = settings->replacement;
            ctx.set(xmm3, ctx.get<float>(xmm3) * settings->scale);
        }).apply();
    if (!patch) {
        std::println("runtime failed: {}", patch.error().format());
        return 1;
    }
    const auto after = function(&settings, 2.0f);
    auto restored = patch->restore();
    if (!restored) return 1;
    const auto original = function(&settings, 2.0f);
    std::println("before: {}, patched: {}, restored: {}", before, after, original);
    return before == 9 && after == 48 && original == 9 ? 0 : 1;
}
