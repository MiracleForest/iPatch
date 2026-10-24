// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ipatch/config.hpp"
#include "ipatch/error.hpp"
#include "ipatch/range.hpp"

namespace ipatch {

struct Section {
    std::string name;
    Range range;
    std::uint32_t characteristics{0};

    [[nodiscard]] bool executable() const noexcept;
    [[nodiscard]] bool readable() const noexcept;
    [[nodiscard]] bool writable() const noexcept;
};

/// A loaded PE image (EXE or DLL).
class IPATCH_API Module {
public:
    Module() = default;

    /// The executable currently running.
    [[nodiscard]] static Module main() noexcept;

    /// Finds a module by base name or full path (case-insensitive).
    [[nodiscard]] static Result<Module> find(std::string_view name);

    /// Finds the module that contains `address`.
    [[nodiscard]] static Result<Module> containing(const void* address);

    [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr && base_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    [[nodiscard]] void* handle() const noexcept { return handle_; }
    [[nodiscard]] std::byte* base() const noexcept { return base_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] Range range() const noexcept { return Range::from(base_, size_); }

    /// Returns the address at `rva` bytes from the module base.
    ///
    /// This is convenient for addresses copied from a disassembler:
    ///
    ///     auto site = module.at(0x1C483BC);
    ///
    /// No bounds check is performed. Returns `nullptr` for an invalid module.
    [[nodiscard]] std::byte* at(std::uintptr_t rva) const noexcept {
        return base_ ? base_ + rva : nullptr;
    }

    [[nodiscard]] std::string name() const;
    [[nodiscard]] std::string path() const;

    /// All PE sections, in image order.
    [[nodiscard]] std::vector<Section> sections() const;

    /// Bounding range of executable sections; may include intervening data/gaps.
    /// Prefer scan(...).in(module), which visits individual sections.
    [[nodiscard]] Range executable_range() const;

    [[nodiscard]] Result<Range> section(std::string_view name) const;

    /// Shorthand for section(".text").
    [[nodiscard]] Result<Range> text() const;

private:
    friend IPATCH_API Result<Module> module_from_handle(void* handle);

    void* handle_{nullptr};
    std::byte* base_{nullptr};
    std::size_t size_{0};
};

/// Finds a module by address, or the closest module + offset.
[[nodiscard]] IPATCH_API Result<Module> module_from_handle(void* handle);

} // namespace ipatch
