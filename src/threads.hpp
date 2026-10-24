// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "ipatch/error.hpp"
#include "ipatch/range.hpp"
#include "win.hpp"

namespace ipatch::detail {

struct RipRemap {
    std::uintptr_t old_begin{0};
    std::uintptr_t old_end{0};
    std::uintptr_t new_begin{0};
    std::size_t old_to_new_delta{0}; // simple offset mapping

    [[nodiscard]] bool maps(std::uintptr_t rip) const noexcept {
        return rip >= old_begin && rip < old_end;
    }
};

/// Suspends every other thread in the current process while a code patch is
/// installed. Also remaps instruction pointers that point into the overwritten
/// prologue, which is what MinHook/SafetyHook do to avoid executing torn code.
class ThreadFreezer {
public:
    explicit ThreadFreezer(bool enabled = true) noexcept : enabled_(enabled) {}
    ~ThreadFreezer();

    ThreadFreezer(const ThreadFreezer&) = delete;
    ThreadFreezer& operator=(const ThreadFreezer&) = delete;

    Status freeze();
    Status remap_rips(std::span<const RipRemap> remaps);
    [[nodiscard]] bool any_rip_in(std::span<const Range> ranges) const noexcept;
    void thaw() noexcept;

    [[nodiscard]] bool frozen() const noexcept { return frozen_; }
    [[nodiscard]] std::size_t thread_count() const noexcept { return threads_.size(); }

private:
    struct ThreadEntry {
        HANDLE handle{nullptr};
        DWORD id{0};
        CONTEXT context{};
        bool context_valid{false};
    };

    bool enabled_{true};
    bool frozen_{false};
    std::vector<ThreadEntry> threads_;
};

} // namespace ipatch::detail
