// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ipatch/config.hpp"
#include "ipatch/error.hpp"
#include "ipatch/range.hpp"

namespace ipatch {

/// A byte signature with wildcards and optional gap-separated segments.
///
/// Segment 0 starts at the reported match address. Each additional segment must
/// occur `gap_min..gap_max` bytes after the previous segment. This turns
/// multiple independent search conditions into one composite pattern:
///
///     auto pattern = Pattern::parse("48 8B 05 ?? ?? ?? ??");
///     if (pattern) pattern->then("E8 ?? ?? ?? ??", 8, 64);
class IPATCH_API Pattern {
public:
    struct Segment {
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint8_t> mask; // 0xFF = exact, 0x00 = wildcard, nibbles allowed
        std::size_t gap_min{0};         // gap before this segment (ignored for segment 0)
        std::size_t gap_max{0};

        [[nodiscard]] std::size_t size() const noexcept { return bytes.size(); }
        [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
        [[nodiscard]] std::size_t literal_bytes() const noexcept;
        [[nodiscard]] bool matches(const std::byte* at) const noexcept;
    };

    Pattern() = default;

    /// Parses "48 8B ?? ??", "4? 8B", or compact "488B????????".
    [[nodiscard]] static Result<Pattern> parse(std::string_view text);

    [[nodiscard]] static Result<Pattern> from_bytes(std::span<const std::uint8_t> bytes,
                                                    std::span<const std::uint8_t> mask = {});

    /// Exact text bytes (no wildcard parsing or encoding conversion). Embedded
    /// NULs are preserved; null_terminated appends one additional terminator.
    [[nodiscard]] static Result<Pattern> from_string(std::string_view text,
                                                    bool null_terminated = false);
    /// UTF-16 code units encoded little-endian, independent of wchar_t.
    [[nodiscard]] static Result<Pattern> from_string(std::u16string_view text,
                                                    bool null_terminated = false);

    /// Adds one byte. mask is a per-bit wildcard mask (0xFF exact).
    Pattern& add(std::uint8_t value, std::uint8_t mask = 0xFF);
    Pattern& add(std::byte value) { return add(std::to_integer<std::uint8_t>(value)); }
    Pattern& add_wildcard(std::size_t count = 1);
    Pattern& add_bytes(std::span<const std::uint8_t> bytes);
    Pattern& add_bytes(std::initializer_list<std::uint8_t> bytes) {
        return add_bytes(std::span(bytes.begin(), bytes.size()));
    }

    static constexpr std::size_t use_pending_gap = static_cast<std::size_t>(-1);

    /// Appends a new gap-separated segment.
    Pattern& then(Pattern next, std::size_t gap_min = use_pending_gap,
                  std::size_t gap_max = use_pending_gap);
    Pattern& then(std::string_view signature, std::size_t gap_min = use_pending_gap,
                  std::size_t gap_max = use_pending_gap);
    Pattern& then(std::span<const std::uint8_t> bytes,
                  std::size_t gap_min = use_pending_gap,
                  std::size_t gap_max = use_pending_gap);

    /// Gap used by the next then() call.
    Pattern& within(std::size_t gap_min, std::size_t gap_max);
    Pattern& within(std::size_t max_gap) { return within(0, max_gap); }

    /// Optional diagnostic name, copied into Match::pattern_name.
    Pattern& named(std::string name) &;
    Pattern&& named(std::string name) &&;

    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] const Error& error() const noexcept { return error_; }

    [[nodiscard]] const std::vector<Segment>& segments() const noexcept { return segments_; }
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;     // bytes of segment 0
    [[nodiscard]] std::size_t min_size() const noexcept; // minimum total span
    [[nodiscard]] std::size_t max_size() const noexcept; // maximum total span

    /// True if the full pattern (including all segments) matches at `address`.
    /// Caller must supply max_size() readable bytes. For bounded input use find_first().
    [[nodiscard]] bool matches(const std::byte* address) const noexcept;

    /// Scans a range. Returns the address of segment 0.
    [[nodiscard]] std::optional<std::byte*> find_first(Range range,
                                                       std::size_t alignment = 1) const;

    /// Finds all matches, including overlaps. Alignment is relative to range.begin.
    [[nodiscard]] std::vector<std::byte*> find_all(Range range, std::size_t alignment = 1,
                                                   std::size_t limit = 0) const;

    [[nodiscard]] std::string to_string() const;

private:
    friend class ScanQuery;

    std::vector<Segment> segments_;
    std::string name_;
    Error error_{};
    std::size_t pending_gap_min_{0};
    std::size_t pending_gap_max_{64};
};

/// A set of alternative patterns. Used for "any of these signatures" searches.
using PatternSet = std::vector<Pattern>;

} // namespace ipatch
