// SPDX-License-Identifier: MIT
#include "memory.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <tuple>
#include <vector>

namespace ipatch::detail {
namespace {

constexpr std::size_t    kPageSize              = 0x1000;
constexpr std::uintptr_t kTwoGiB                = 0x80000000ull;
constexpr std::uintptr_t kAllocationGranularity = 0x10000;

[[nodiscard]] bool protects_read(DWORD protect) noexcept {
    protect &= 0xFF;
    return protect == PAGE_READONLY || protect == PAGE_READWRITE || protect == PAGE_WRITECOPY
        || protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] bool protects_execute(DWORD protect) noexcept {
    protect &= 0xFF;
    return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE_READWRITE
        || protect == PAGE_EXECUTE_WRITECOPY;
}

struct AddressRequirements {
    void*       lowest_starting_address{nullptr};
    void*       highest_ending_address{nullptr};
    std::size_t alignment{0};
};

struct ExtendedParameter {
    // MEM_EXTENDED_PARAMETER::Type is the low 8 bits and Reserved must be 0.
    std::uint64_t type_value;
    union {
        std::uint64_t ulong64_value;
        void*         pointer;
        std::size_t   size;
        void*         handle;
        std::uint32_t ulong_value;
    };
};

static_assert(sizeof(ExtendedParameter) == 16);

constexpr std::uint64_t kAddressRequirementsType = 1;

using VirtualAlloc2Fn = void*(WINAPI*)(HANDLE, void*, std::size_t, unsigned long, unsigned long, void*, unsigned long);

[[nodiscard]] VirtualAlloc2Fn resolve_virtual_alloc2() noexcept {
    static VirtualAlloc2Fn proc_fn = []() -> VirtualAlloc2Fn {
        HMODULE module = ::GetModuleHandleW(L"kernelbase.dll");
        if (!module) module = ::GetModuleHandleW(L"kernel32.dll");
        if (!module) return nullptr;
        const FARPROC   proc = ::GetProcAddress(module, "VirtualAlloc2");
        VirtualAlloc2Fn fn   = nullptr;
        static_assert(sizeof(fn) == sizeof(proc));
        std::memcpy(&fn, &proc, sizeof(fn));
        return fn;
    }();
    return proc_fn;
}

[[nodiscard]] bool try_virtual_alloc2(void* target, std::size_t size, std::size_t alignment, void*& out) {
    const auto fn = resolve_virtual_alloc2();
    if (!fn) return false;

    const auto           target_value = reinterpret_cast<std::uintptr_t>(target);
    const std::uintptr_t low          = target_value > kTwoGiB ? target_value - kTwoGiB : 0;
    const std::uintptr_t high         = target_value > std::numeric_limits<std::uintptr_t>::max() - kTwoGiB
                                          ? std::numeric_limits<std::uintptr_t>::max()
                                          : target_value + kTwoGiB;

    AddressRequirements requirements{};
    requirements.lowest_starting_address = reinterpret_cast<void*>(low);
    requirements.highest_ending_address  = reinterpret_cast<void*>(high);
    requirements.alignment               = alignment;

    ExtendedParameter parameter{};
    parameter.type_value = kAddressRequirementsType;
    parameter.pointer    = &requirements;

    out = fn(::GetCurrentProcess(), nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &parameter, 1);
    return out != nullptr;
}

[[nodiscard]] bool try_alloc_at(std::uintptr_t address, std::size_t size, void*& out) {
    out = ::VirtualAlloc(reinterpret_cast<void*>(address), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return out != nullptr;
}

[[nodiscard]] void* allocate_near_fallback(void* target, std::size_t size, void* hint) {
    const auto target_value = reinterpret_cast<std::uintptr_t>(target ? target : hint);
    if (target_value == 0) return nullptr;

    const std::uintptr_t low  = target_value > kTwoGiB ? target_value - kTwoGiB : kAllocationGranularity;
    const std::uintptr_t high = target_value > std::numeric_limits<std::uintptr_t>::max() - kTwoGiB
                                  ? std::numeric_limits<std::uintptr_t>::max()
                                  : target_value + kTwoGiB;

    // First try exact hints surrounding the target. This is cheap and usually
    // succeeds for patch libraries because the address space is sparse.
    if (hint) {
        void* out = nullptr;
        if (try_alloc_at(reinterpret_cast<std::uintptr_t>(hint), size, out)) return out;
    }
    const std::uintptr_t aligned_target = align_down(target_value, kAllocationGranularity);
    for (std::uintptr_t delta = kAllocationGranularity; delta < kTwoGiB; delta += kAllocationGranularity) {
        void* out = nullptr;
        if (aligned_target + delta >= aligned_target && try_alloc_at(aligned_target + delta, size, out)) {
            return out;
        }
        if (aligned_target > delta && try_alloc_at(aligned_target - delta, size, out)) {
            return out;
        }
        if (delta > kAllocationGranularity * 512) break; // keep startup latency reasonable
    }

    // Then walk free regions with VirtualQuery and pick the closest one.
    std::uintptr_t cursor        = align_down(low, kAllocationGranularity);
    std::uintptr_t best          = 0;
    std::uintptr_t best_distance = std::numeric_limits<std::uintptr_t>::max();
    int            queries       = 0;
    while (cursor < high && queries++ < 8192) {
        MEMORY_BASIC_INFORMATION info{};
        if (::VirtualQuery(reinterpret_cast<void*>(cursor), &info, sizeof(info)) == 0) break;
        const auto base        = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        const auto region_size = static_cast<std::uintptr_t>(info.RegionSize);
        if (region_size == 0) break;
        if (info.State == MEM_FREE && region_size >= size) {
            const auto distance = base > target_value ? base - target_value : target_value - base;
            if (distance < best_distance) {
                best_distance = distance;
                best          = base;
            }
        }
        const auto next = base + region_size;
        if (next <= cursor) break;
        cursor = align_up(next, kAllocationGranularity);
    }
    if (best) {
        void* out = nullptr;
        if (try_alloc_at(best, size, out)) return out;
    }

    // Last resort: let the OS choose. The caller will reject the result if it
    // is too far for the relocation it needs.
    return ::VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

} // namespace

ProtectionGuard::~ProtectionGuard() {
    // Destructors cannot report a failed protection rollback.
    std::ignore = restore();
}

ProtectionGuard::ProtectionGuard(ProtectionGuard&& other) noexcept : entries_(std::move(other.entries_)) {
    other.entries_.clear();
}

ProtectionGuard& ProtectionGuard::operator=(ProtectionGuard&& other) noexcept {
    if (this != &other) {
        // Move assignment is noexcept; rollback errors cannot be propagated.
        std::ignore = restore();
        entries_    = std::move(other.entries_);
        other.entries_.clear();
    }
    return *this;
}

Result<ProtectionGuard> ProtectionGuard::make(std::span<const Range> ranges) {
    ProtectionGuard guard;
    for (const auto& range : ranges) {
        if (range.empty()) continue;
        auto       address = reinterpret_cast<std::uintptr_t>(range.begin);
        const auto end     = reinterpret_cast<std::uintptr_t>(range.end);
        while (address < end) {
            const auto page        = align_down(address, kPageSize);
            const auto page_end    = page + kPageSize;
            const auto chunk_end   = std::min(end, page_end);
            DWORD      old_protect = 0;
            if (!::VirtualProtect(
                    reinterpret_cast<void*>(page),
                    chunk_end - page,
                    PAGE_EXECUTE_READWRITE,
                    &old_protect
                )) {
                // Best-effort rollback of pages changed earlier in this loop.
                std::ignore = guard.restore();
                return fail(
                    ErrorCode::access_denied,
                    "VirtualProtect failed at " + hex(page) + ": " + win32_message(::GetLastError())
                );
            }
            guard.entries_.push_back(Entry{reinterpret_cast<void*>(page), chunk_end - page, old_protect});
            address = chunk_end;
        }
    }
    return guard;
}

Status ProtectionGuard::restore() {
    Status result = success();
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
        DWORD ignored = 0;
        if (!::VirtualProtect(it->address, it->size, it->old_protect, &ignored) && result) {
            result = fail(ErrorCode::system_error, "VirtualProtect restore failed: " + win32_message(::GetLastError()));
        }
    }
    entries_.clear();
    return result;
}

Status write_memory(void* address, std::span<const std::byte> bytes) {
    if (!address && !bytes.empty()) {
        return fail(ErrorCode::invalid_argument, "write_memory: null address");
    }
    if (bytes.empty()) return success();

    Range range = Range::from(address, bytes.size());
    auto  guard = ProtectionGuard::make(std::span<const Range>(&range, 1));
    if (!guard) return std::unexpected(guard.error());

    std::memcpy(address, bytes.data(), bytes.size());
    flush_instruction_cache(range);
    return guard->restore();
}

Result<std::vector<std::byte>> read_memory(const void* address, std::size_t size) {
    if (!address && size != 0) {
        return fail(ErrorCode::invalid_argument, "read_memory: null address");
    }
    if (!is_readable(address, size)) {
        return fail(ErrorCode::access_denied, "read_memory: range is not readable");
    }
    std::vector<std::byte> bytes(size);
    if (size) std::memcpy(bytes.data(), address, size);
    return bytes;
}

static bool is_accessible(const void* address, std::size_t size, bool writable) noexcept {
    if (!address) return false;
    auto       cursor = reinterpret_cast<std::uintptr_t>(address);
    const auto end    = cursor + size;
    if (end < cursor) return false;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (::VirtualQuery(reinterpret_cast<void*>(cursor), &info, sizeof(info)) == 0) return false;
        if (info.State != MEM_COMMIT) return false;
        if ((info.Protect & PAGE_GUARD) != 0 || (info.Protect & PAGE_NOACCESS) != 0) return false;
        if (!protects_read(info.Protect)) return false;
        const auto protection = info.Protect & 0xff;
        if (writable && protection != PAGE_READWRITE && protection != PAGE_WRITECOPY
            && protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)
            return false;
        const auto base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        const auto next = base + info.RegionSize;
        if (next <= cursor) return false;
        cursor = next;
    }
    return true;
}

bool is_readable(const void* address, std::size_t size) noexcept { return is_accessible(address, size, false); }

bool is_writable(const void* address, std::size_t size) noexcept { return is_accessible(address, size, true); }

bool is_executable(const void* address) noexcept {
    if (!address) return false;
    MEMORY_BASIC_INFORMATION info{};
    if (::VirtualQuery(address, &info, sizeof(info)) == 0) return false;
    return info.State == MEM_COMMIT && (info.Protect & PAGE_GUARD) == 0 && protects_execute(info.Protect);
}

Result<Range> committed_region(const void* address) {
    if (!address) return fail(ErrorCode::invalid_argument, "address is null");
    MEMORY_BASIC_INFORMATION info{};
    if (::VirtualQuery(address, &info, sizeof(info)) == 0) {
        return fail(ErrorCode::system_error, "VirtualQuery failed: " + win32_message(::GetLastError()));
    }
    if (info.State != MEM_COMMIT) {
        return fail(ErrorCode::not_found, "address is not committed");
    }
    auto* base = static_cast<std::byte*>(info.BaseAddress);
    return Range{base, base + info.RegionSize};
}

Allocation::~Allocation() { reset(); }

Allocation::Allocation(Allocation&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

Allocation& Allocation::operator=(Allocation&& other) noexcept {
    if (this != &other) {
        reset();
        data_       = other.data_;
        size_       = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void Allocation::reset() noexcept {
    if (data_) {
        ::VirtualFree(data_, 0, MEM_RELEASE);
        data_ = nullptr;
        size_ = 0;
    }
}

Result<Allocation> allocate_near(void* target, std::size_t size, void* hint) {
    if (size == 0) return fail(ErrorCode::invalid_argument, "allocation size is zero");
    const std::size_t rounded = align_up(size, kPageSize);

    void* memory = nullptr;
    if (!try_virtual_alloc2(target ? target : hint, rounded, kAllocationGranularity, memory)) {
        memory = allocate_near_fallback(target, rounded, hint);
    }
    if (!memory) {
        return fail(
            ErrorCode::allocation_failed,
            "could not allocate executable memory: " + win32_message(::GetLastError())
        );
    }

    Allocation allocation;
    allocation.data_ = memory;
    allocation.size_ = rounded;
    return allocation;
}

void flush_instruction_cache(Range range) noexcept {
    if (!range.empty()) {
        ::FlushInstructionCache(::GetCurrentProcess(), range.begin, range.size());
    }
}

} // namespace ipatch::detail
