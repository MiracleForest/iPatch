// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <array>
#include <bit>
#include <expected>
#include <functional>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "ipatch/config.hpp"
#include "ipatch/error.hpp"
#include "ipatch/module.hpp"
#include "ipatch/pattern.hpp"
#include "ipatch/range.hpp"

namespace ipatch {

struct Match {
    std::byte* address{nullptr};
    std::size_t pattern_index{0};
    std::string pattern_name;

    [[nodiscard]] explicit operator bool() const noexcept { return address != nullptr; }
};

/// A monadic scan result, intentionally shaped like std::optional:
///
///     auto ptr = scan("75 06 41 83 F8 06")
///                    .first()
///                    .or_else([] { log(); return std::optional<std::byte*>{}; })
///                    .transform([](std::byte* p) { return p + 5; })
///                    .value();
class IPATCH_API MatchResult {
public:
    MatchResult() : value_(std::unexpect, Error{ErrorCode::not_found, "pattern not found"}) {}
    explicit MatchResult(std::byte* address)
        : value_(address ? std::expected<std::byte*, Error>(address)
                         : std::expected<std::byte*, Error>(
                               std::unexpect, Error{ErrorCode::not_found, "pattern not found"})) {}
    explicit MatchResult(std::nullptr_t) : value_(std::unexpect, Error{ErrorCode::not_found, "pattern not found"}) {}
    explicit MatchResult(Error error) : value_(std::unexpect, std::move(error)) {}
    explicit MatchResult(std::expected<std::byte*, Error> value) : value_(std::move(value)) {
        if (value_ && !*value_)
            value_ = std::unexpected(Error{ErrorCode::not_found, "result contains a null address"});
    }

    [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    /// Returns nullptr when the scan failed. Use error() to inspect the failure.
    [[nodiscard]] std::byte* value() const noexcept { return value_ ? *value_ : nullptr; }
    [[nodiscard]] std::byte* address() const noexcept { return value(); }
    [[nodiscard]] std::byte* value_or(std::byte* fallback) const noexcept {
        return value_ ? *value_ : fallback;
    }
    [[nodiscard]] const Error& error() const noexcept {
        static const Error no_error{};
        return value_ ? no_error : value_.error();
    }

    /// Checked address arithmetic. Does not check allocation bounds or readability.
    [[nodiscard]] MatchResult offset(std::ptrdiff_t bytes) const;

    /// Reads a signed little-endian disp32 at address + displacement_offset.
    /// Target = address + next_instruction_offset + disp32.
    /// CALL E8: rel32(1, 5); MOV/LEA [RIP+disp32]: rel32(3, 7).
    /// Only the displacement is read; the target need not be readable.
    [[nodiscard]] MatchResult rel32(std::ptrdiff_t displacement_offset = 0,
                                    std::ptrdiff_t next_instruction_offset = 4) const;

    /// Converts the address to an RVA, rejecting addresses outside the module.
    [[nodiscard]] Result<std::uintptr_t> rva(const Module& module) const;

    /// Copies a typed value without alignment assumptions. Checks readability;
    /// the caller must still keep the memory alive throughout the read.
    template <typename T>
        requires (std::is_trivially_copyable_v<T> && !std::is_const_v<T> &&
                  !std::is_volatile_v<T> && !std::is_array_v<T>)
    [[nodiscard]] Result<T> read() const {
        std::array<std::byte, sizeof(T)> bytes;
        auto copied = copy_to(bytes);
        if (!copied) return std::unexpected(copied.error());
        return std::bit_cast<T>(bytes);
    }

    /// Borrows a live T object at this address (not a pointer stored there).
    /// Checks alignment and all sizeof(T) bytes: const T needs readable pages,
    /// mutable T needs readable/writable pages. Does not change protection.
    /// Caller guarantees the matching object's lifetime/type and synchronization.
    /// Direct writes are immediate, outside Patch's apply/restore transaction.
    template <typename T>
        requires (std::is_object_v<T> && !std::is_array_v<T> && requires { sizeof(T); })
    [[nodiscard]] Result<T*> ptr() const {
        auto checked = check_borrow(sizeof(T), alignof(T), !std::is_const_v<T>);
        if (!checked) return std::unexpected(checked.error());
        return reinterpret_cast<T*>(*value_);
    }

    /// Fallible reference access; use result->get() after checking the result.
    template <typename T>
        requires (std::is_object_v<T> && !std::is_array_v<T> && requires { sizeof(T); })
    [[nodiscard]] Result<std::reference_wrapper<T>> ref() const {
        auto pointer = ptr<T>();
        if (!pointer) return std::unexpected(pointer.error());
        return std::ref(**pointer);
    }

    template <typename F>
        requires std::invocable<F, std::byte*>
    [[nodiscard]] MatchResult transform(F&& fn) const {
        if (!value_) return *this;
        using R = std::invoke_result_t<F, std::byte*>;
        if constexpr (std::is_void_v<R>) {
            std::invoke(std::forward<F>(fn), *value_);
            return *this;
        } else if constexpr (std::is_convertible_v<R, std::byte*>) {
            return MatchResult(static_cast<std::byte*>(std::invoke(std::forward<F>(fn), *value_)));
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, std::optional<std::byte*>>) {
            auto next = std::invoke(std::forward<F>(fn), *value_);
            if (!next) return MatchResult(Error{ErrorCode::not_found, "pattern transform returned nullopt"});
            return MatchResult(*next);
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, std::expected<std::byte*, Error>>) {
            return MatchResult(std::invoke(std::forward<F>(fn), *value_));
        } else {
            static_assert(std::is_void_v<R>, "transform must return void, byte*, optional<byte*>, or expected<byte*, Error>");
        }
    }

    template <typename F>
        requires (std::invocable<F, const Error&> || std::invocable<F>)
    [[nodiscard]] MatchResult or_else(F&& fn) const {
        if (value_) return *this;
        // Prefer the error-aware form if a callable supports both signatures.
        auto invoke = [&]() -> decltype(auto) {
            if constexpr (std::invocable<F, const Error&>)
                return std::invoke(std::forward<F>(fn), value_.error());
            else return std::invoke(std::forward<F>(fn));
        };
        using R = decltype(invoke());
        if constexpr (std::is_void_v<R>) {
            invoke();
            return *this;
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, MatchResult>) {
            return invoke();
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, std::optional<std::byte*>>) {
            auto next = invoke();
            if (!next) return *this;
            return MatchResult(*next);
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, std::expected<std::byte*, Error>>) {
            return MatchResult(invoke());
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, Error>) {
            return MatchResult(invoke());
        } else if constexpr (std::is_convertible_v<R, std::byte*>) {
            return MatchResult(static_cast<std::byte*>(invoke()));
        } else {
            static_assert(std::is_void_v<R>, "or_else must return void, byte*, MatchResult, optional<byte*>, or expected<byte*, Error>");
        }
    }

    template <typename F>
        requires std::invocable<F, std::byte*>
    [[nodiscard]] MatchResult and_then(F&& fn) const {
        if (!value_) return *this;
        using R = std::invoke_result_t<F, std::byte*>;
        if constexpr (std::is_same_v<std::remove_cvref_t<R>, MatchResult>) {
            return std::invoke(std::forward<F>(fn), *value_);
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, std::optional<std::byte*>>) {
            auto next = std::invoke(std::forward<F>(fn), *value_);
            if (!next) return MatchResult(Error{ErrorCode::not_found, "pattern and_then returned nullopt"});
            return MatchResult(*next);
        } else if constexpr (std::is_same_v<std::remove_cvref_t<R>, std::expected<std::byte*, Error>>) {
            return MatchResult(std::invoke(std::forward<F>(fn), *value_));
        } else {
            return transform(std::forward<F>(fn));
        }
    }

    [[nodiscard]] const std::expected<std::byte*, Error>& raw() const & noexcept { return value_; }
    [[nodiscard]] std::expected<std::byte*, Error> raw() && noexcept { return std::move(value_); }
    [[nodiscard]] std::expected<std::byte*, Error> raw() const && { return value_; }

private:
    [[nodiscard]] Status check_borrow(std::size_t size, std::size_t alignment, bool writable) const;
    [[nodiscard]] Status copy_to(std::span<std::byte> output) const;
    std::expected<std::byte*, Error> value_;
};

/// A scanner that accepts any number of alternative signatures and several
/// independent ranges. The first match across all patterns/ranges wins.
class IPATCH_API ScanQuery {
public:
    ScanQuery() = default;
    explicit ScanQuery(Pattern pattern);
    explicit ScanQuery(std::string_view signature);

    ScanQuery& add(Pattern pattern);
    ScanQuery& add(std::string_view signature);
    ScanQuery& add(std::initializer_list<std::string_view> signatures);
    ScanQuery& add(PatternSet patterns);
    ScanQuery& add(std::initializer_list<Pattern> patterns);

    /// Explicit empty ranges/invalid modules are errors, never default scopes.
    /// Selected ranges must remain readable for the duration of the scan.
    ScanQuery& in(Range range);
    ScanQuery& in(Module module);
    ScanQuery& in_main_module();
    ScanQuery& in_process(bool enabled = true);

    /// Only visit PAGE_EXECUTE* regions when scanning a module/process.
    ScanQuery& executable_only(bool enabled = true);

    /// Require (address - range.begin) % alignment == 0, relative to each
    /// normalized range (overlapping/adjacent input ranges are merged).
    ScanQuery& alignment(std::size_t alignment);

    /// Maximum number of matches returned by all(). 0 = unlimited.
    ScanQuery& limit(std::size_t count);

    [[nodiscard]] const std::vector<Pattern>& patterns() const noexcept { return patterns_; }

    /// All matches, sorted by address, then pattern index.
    [[nodiscard]] Result<std::vector<Match>> all() const;

    /// Earliest match. Scan errors are carried in MatchResult.
    [[nodiscard]] MatchResult first() const;

    /// Strict variant for callers that prefer std::expected.
    [[nodiscard]] Result<Match> require_first() const;

    /// Requires exactly one match across all patterns and ranges.
    ///
    /// This is the safe counterpart to first(): a missing signature returns
    /// `not_found`, and a signature that matches more than once returns
    /// `ambiguous` instead of silently choosing the earliest address. The
    /// query's `limit()` is ignored so a truncated result cannot hide duplicate
    /// matches.
    [[nodiscard]] Result<Match> require_unique() const;

    /// Chainable unique result, preserving not_found/ambiguous diagnostics.
    [[nodiscard]] MatchResult unique() const;

private:
    [[nodiscard]] Result<std::vector<Range>> resolve_ranges() const;
    [[nodiscard]] Result<std::vector<Match>> scan_ranges(const std::vector<Range>& ranges,
                                                         std::size_t stop_after) const;

    std::vector<Pattern> patterns_;
    std::vector<Range> ranges_;
    std::vector<Module> modules_;
    bool process_{false};
    bool executable_only_{true};
    std::size_t alignment_{1};
    std::size_t limit_{0};
    Error error_{};
};

[[nodiscard]] IPATCH_API ScanQuery scan(Pattern pattern);
[[nodiscard]] IPATCH_API ScanQuery scan(std::string_view signature);
[[nodiscard]] IPATCH_API ScanQuery scan(std::initializer_list<std::string_view> signatures);

/// Searches literal text; defaults to readable module sections (including data).
/// Narrow text is matched byte-for-byte; UTF-16 is encoded little-endian.
[[nodiscard]] IPATCH_API ScanQuery scan_string(std::string_view text, bool null_terminated = false);
[[nodiscard]] IPATCH_API ScanQuery scan_string(std::u16string_view text, bool null_terminated = false);

/// Unique text match followed by checked byte offset. Empty text is rejected.
[[nodiscard]] IPATCH_API Result<std::byte*> locate_string(Range range, std::string_view text,
    std::ptrdiff_t offset = 0, bool null_terminated = false);
[[nodiscard]] IPATCH_API Result<std::byte*> locate_string(Range range, std::u16string_view text,
    std::ptrdiff_t offset = 0, bool null_terminated = false);
[[nodiscard]] IPATCH_API Result<std::byte*> locate_string(const Module& module, std::string_view text,
    std::ptrdiff_t offset = 0, bool null_terminated = false);
[[nodiscard]] IPATCH_API Result<std::byte*> locate_string(const Module& module, std::u16string_view text,
    std::ptrdiff_t offset = 0, bool null_terminated = false);

/// Finds exactly one occurrence of `signature` and returns `match + offset`.
///
/// This is the compact form of the common safe-locate sequence:
///
///     auto site = locate(module, kSiteSignature, 15);
///     auto abort = locate(module, kAbortSignature);
///     if (!site || !abort) { ... }
///
/// A missing signature returns `not_found`; multiple matches return
/// `ambiguous`. An empty range or invalid module is rejected instead of
/// falling back to the main module.
[[nodiscard]] IPATCH_API Result<std::byte*> locate(Range range,
                                                   std::string_view signature,
                                                   std::ptrdiff_t offset = 0);

/// Scans the module's executable sections. See the Range overload.
[[nodiscard]] IPATCH_API Result<std::byte*> locate(const Module& module,
                                                   std::string_view signature,
                                                   std::ptrdiff_t offset = 0);

} // namespace ipatch
