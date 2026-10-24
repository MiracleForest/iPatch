// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "ipatch/error.hpp"
#include "ipatch/range.hpp"
#include "win.hpp"

namespace ipatch::detail {

/// Temporarily makes pages writable. Restores the original protection on
/// destruction. Multiple disjoint ranges are supported.
class ProtectionGuard {
public:
    ProtectionGuard() = default;
    ~ProtectionGuard();

    ProtectionGuard(const ProtectionGuard&) = delete;
    ProtectionGuard& operator=(const ProtectionGuard&) = delete;
    ProtectionGuard(ProtectionGuard&& other) noexcept;
    ProtectionGuard& operator=(ProtectionGuard&& other) noexcept;

    static Result<ProtectionGuard> make(std::span<const Range> ranges);

    Status restore();
    [[nodiscard]] bool active() const noexcept { return !entries_.empty(); }

private:
    struct Entry {
        void* address{nullptr};
        std::size_t size{0};
        DWORD old_protect{0};
    };

    std::vector<Entry> entries_;
};

/// Changes protection, copies bytes, flushes the instruction cache, and
/// restores protection. Intended for small code patches.
[[nodiscard]] Status write_memory(void* address, std::span<const std::byte> bytes);

[[nodiscard]] Result<std::vector<std::byte>> read_memory(const void* address, std::size_t size);

[[nodiscard]] bool is_readable(const void* address, std::size_t size) noexcept;
[[nodiscard]] bool is_writable(const void* address, std::size_t size) noexcept;
[[nodiscard]] bool is_executable(const void* address) noexcept;

[[nodiscard]] Result<Range> committed_region(const void* address);

/// An executable allocation that is automatically released.
class Allocation {
public:
    Allocation() = default;
    ~Allocation();

    Allocation(const Allocation&) = delete;
    Allocation& operator=(const Allocation&) = delete;
    Allocation(Allocation&& other) noexcept;
    Allocation& operator=(Allocation&& other) noexcept;

    [[nodiscard]] void* data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool valid() const noexcept { return data_ != nullptr; }
    [[nodiscard]] Range range() const noexcept { return Range::from(data_, size_); }

    void reset() noexcept;

private:
    friend Result<Allocation> allocate_near(void*, std::size_t, void*);

    void* data_{nullptr};
    std::size_t size_{0};
};

/// Allocates RWX memory as close as possible to `target`, preferably within
/// +/-2 GiB so rel32 and RIP-relative displacements still fit.
[[nodiscard]] Result<Allocation> allocate_near(void* target, std::size_t size,
                                               void* hint = nullptr);

void flush_instruction_cache(Range range) noexcept;

} // namespace ipatch::detail
