// SPDX-License-Identifier: MIT
#include "ipatch/pattern.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iterator>
#include <limits>
#include <string>

namespace ipatch {
namespace {

[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.remove_suffix(1);
    }
    return text;
}

[[nodiscard]] int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

struct Anchor {
    std::size_t offset{0};
    std::size_t length{0};
};

[[nodiscard]] std::size_t saturated_add(std::size_t a, std::size_t b) noexcept {
    const auto maximum = std::numeric_limits<std::size_t>::max();
    return b > maximum - a ? maximum : a + b;
}

[[nodiscard]] Anchor longest_anchor(const Pattern::Segment& segment) noexcept {
    Anchor      best{};
    std::size_t run_start  = 0;
    std::size_t run_length = 0;
    for (std::size_t i = 0; i < segment.bytes.size(); ++i) {
        if (segment.mask[i] == 0xFF) {
            if (run_length == 0) run_start = i;
            ++run_length;
            if (run_length > best.length) {
                best.offset = run_start;
                best.length = run_length;
            }
        } else {
            run_length = 0;
        }
    }
    return best;
}

[[nodiscard]] bool segment_matches_at(const Pattern::Segment& segment, const std::byte* at) noexcept {
    if (!at) return false;
    for (std::size_t i = 0; i < segment.bytes.size(); ++i) {
        const auto value = std::to_integer<std::uint8_t>(at[i]);
        if ((value & segment.mask[i]) != (segment.bytes[i] & segment.mask[i])) return false;
    }
    return true;
}

/// Finds the first occurrence of `segment` in [begin, end).
[[nodiscard]] const std::byte* find_segment(
    const Pattern::Segment& segment,
    const std::byte*        begin,
    const std::byte*        end
) noexcept {
    if (!begin || !end || begin > end) return nullptr;
    const std::size_t available = static_cast<std::size_t>(end - begin);
    const std::size_t length    = segment.size();
    if (length == 0) return begin;
    if (length > available) return nullptr;

    const auto*  data   = reinterpret_cast<const std::uint8_t*>(begin);
    const Anchor anchor = longest_anchor(segment);

    if (anchor.length == 0) {
        for (std::size_t i = 0; i + length <= available; ++i) {
            if (segment_matches_at(segment, begin + i)) return begin + i;
        }
        return nullptr;
    }

    if (anchor.length == 1) {
        const std::uint8_t needle = segment.bytes[anchor.offset];
        for (std::size_t i = 0; i + length <= available; ++i) {
            if (data[i + anchor.offset] == needle && segment_matches_at(segment, begin + i)) {
                return begin + i;
            }
        }
        return nullptr;
    }

    std::array<std::size_t, 256> skip{};
    skip.fill(anchor.length);
    for (std::size_t i = 0; i + 1 < anchor.length; ++i) {
        skip[segment.bytes[anchor.offset + i]] = anchor.length - 1 - i;
    }

    std::size_t pos = 0;
    while (pos + anchor.offset + anchor.length <= available) {
        const std::size_t anchor_start = pos + anchor.offset;
        std::size_t       j            = anchor.length;
        while (j > 0) {
            const std::uint8_t current = data[anchor_start + j - 1];
            if (current != segment.bytes[anchor.offset + j - 1]) break;
            --j;
        }
        if (j == 0) {
            if (pos + length <= available && segment_matches_at(segment, begin + pos)) {
                return begin + pos;
            }
        }
        const std::size_t tail_index = anchor_start + anchor.length - 1;
        if (tail_index >= available) break;
        const std::uint8_t tail  = data[tail_index];
        pos                     += std::max<std::size_t>(1, skip[tail]);
    }
    return nullptr;
}

[[nodiscard]] bool verify_chain(
    const Pattern&   pattern,
    std::size_t      index,
    const std::byte* previous_start,
    const std::byte* range_begin,
    const std::byte* range_end,
    int&             budget
) noexcept {
    const auto& segments = pattern.segments();
    if (index >= segments.size()) return true;
    if (--budget < 0) return false;

    const auto&      previous     = segments[index - 1];
    const std::byte* previous_end = previous_start + previous.size();
    const auto&      current      = segments[index];

    const std::size_t available       = static_cast<std::size_t>(range_end - range_begin);
    const std::size_t previous_offset = static_cast<std::size_t>(previous_end - range_begin);
    if (previous_offset >= available) return false;

    const auto remaining = available - previous_offset;
    if (current.size() > remaining || current.gap_min > remaining - current.size()) return false;
    const std::size_t min_start  = previous_offset + current.gap_min;
    const std::size_t last_start = previous_offset + std::min(current.gap_max, remaining - current.size());

    for (std::size_t offset = min_start; offset <= last_start; ++offset) {
        if (offset + current.size() > available) break;
        const std::byte* candidate = range_begin + offset;
        if (!segment_matches_at(current, candidate)) continue;
        if (verify_chain(pattern, index + 1, candidate, range_begin, range_end, budget)) return true;
    }
    return false;
}

[[nodiscard]] bool verify_at(const Pattern& pattern, const std::byte* address) noexcept {
    const auto& segments = pattern.segments();
    if (segments.empty() || !segment_matches_at(segments[0], address)) return false;
    const auto span = pattern.max_size();
    if (span > static_cast<std::size_t>(std::numeric_limits<std::ptrdiff_t>::max())) return false;
    int budget = 4096;
    return verify_chain(pattern, 1, address, address, address + span, budget);
}

[[nodiscard]] std::string format_segment(const Pattern::Segment& segment) {
    std::string           out;
    static constexpr char digits[] = "0123456789ABCDEF";
    for (std::size_t i = 0; i < segment.bytes.size(); ++i) {
        if (i) out.push_back(' ');
        const std::uint8_t mask  = segment.mask[i];
        const std::uint8_t value = segment.bytes[i];
        const char         high  = (mask & 0xF0) ? digits[(value >> 4) & 0xF] : '?';
        const char         low   = (mask & 0x0F) ? digits[value & 0xF] : '?';
        out.push_back(high);
        out.push_back(low);
    }
    return out;
}

} // namespace

std::size_t Pattern::Segment::literal_bytes() const noexcept {
    std::size_t count = 0;
    for (const auto mask_value : this->mask) {
        if (mask_value == 0xFF) ++count;
    }
    return count;
}

bool Pattern::Segment::matches(const std::byte* at) const noexcept { return segment_matches_at(*this, at); }

Result<Pattern> Pattern::parse(std::string_view text) {
    text = trim(text);
    if (text.empty()) return fail(ErrorCode::invalid_pattern, "signature is empty");

    std::vector<std::string_view> tokens;
    const bool                    spaced = text == "?" || text.find_first_of(" \t\r\n\v\f") != std::string_view::npos;
    if (spaced) {
        std::size_t i = 0;
        while (i < text.size()) {
            while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
            const std::size_t start = i;
            while (i < text.size() && !std::isspace(static_cast<unsigned char>(text[i]))) ++i;
            if (i > start) tokens.push_back(text.substr(start, i - start));
        }
    } else {
        if (text.size() % 2 != 0) {
            return fail(ErrorCode::invalid_pattern, "compact signature must contain an even number of hex digits");
        }
        for (std::size_t i = 0; i < text.size(); i += 2) {
            tokens.push_back(text.substr(i, 2));
        }
    }

    if (tokens.empty()) return fail(ErrorCode::invalid_pattern, "signature has no bytes");

    Pattern pattern;
    for (auto token : tokens) {
        if (token == "?" || token == "??") {
            pattern.add_wildcard();
            continue;
        }
        if (token.size() != 2) {
            return fail(ErrorCode::invalid_pattern, "invalid signature token: " + std::string(token));
        }
        const int high = token[0] == '?' ? 0 : hex_value(token[0]);
        const int low  = token[1] == '?' ? 0 : hex_value(token[1]);
        if (high < 0 || low < 0) {
            return fail(ErrorCode::invalid_pattern, "invalid signature token: " + std::string(token));
        }
        const std::uint8_t mask =
            static_cast<std::uint8_t>((token[0] == '?' ? 0 : 0xF0) | (token[1] == '?' ? 0 : 0x0F));
        const auto value = static_cast<std::uint8_t>((high << 4) | low);
        pattern.add(value, mask);
    }
    return pattern;
}

Result<Pattern> Pattern::from_bytes(std::span<const std::uint8_t> bytes, std::span<const std::uint8_t> mask) {
    if (bytes.empty()) return fail(ErrorCode::invalid_pattern, "pattern has no bytes");
    if (!mask.empty() && mask.size() != bytes.size()) {
        return fail(ErrorCode::invalid_argument, "mask size does not match pattern size");
    }
    Pattern pattern;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        pattern.add(bytes[i], mask.empty() ? 0xFF : mask[i]);
    }
    return pattern;
}

Result<Pattern> Pattern::from_string(std::string_view text, bool null_terminated) {
    if (text.empty()) return fail(ErrorCode::invalid_pattern, "text is empty");
    Pattern pattern;
    for (unsigned char value : text) pattern.add(value);
    if (null_terminated) pattern.add(0);
    return pattern;
}

Result<Pattern> Pattern::from_string(std::u16string_view text, bool null_terminated) {
    if (text.empty()) return fail(ErrorCode::invalid_pattern, "text is empty");
    Pattern pattern;
    for (char16_t value : text) {
        pattern.add(static_cast<std::uint8_t>(value & 0xFF));
        pattern.add(static_cast<std::uint8_t>(value >> 8));
    }
    if (null_terminated) pattern.add(0).add(0);
    return pattern;
}

Pattern& Pattern::add(std::uint8_t value, std::uint8_t mask) {
    if (segments_.empty()) segments_.push_back(Segment{});
    auto& segment = segments_.back();
    segment.bytes.push_back(static_cast<std::uint8_t>(value & mask));
    segment.mask.push_back(mask);
    return *this;
}

Pattern& Pattern::add_wildcard(std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) add(0, 0);
    return *this;
}

Pattern& Pattern::add_bytes(std::span<const std::uint8_t> bytes) {
    for (auto byte : bytes) add(byte);
    return *this;
}

Pattern& Pattern::then(Pattern next, std::size_t gap_min, std::size_t gap_max) {
    if (!error_.ok()) return *this;
    if (!next.error().ok()) {
        error_ = next.error();
        return *this;
    }
    if (next.empty()) {
        error_ = Error{ErrorCode::invalid_pattern, "empty chained pattern"};
        return *this;
    }
    std::size_t min_gap = gap_min;
    std::size_t max_gap = gap_max;
    if (min_gap == use_pending_gap) min_gap = pending_gap_min_;
    if (max_gap == use_pending_gap) max_gap = pending_gap_max_;
    if (min_gap > max_gap) std::swap(min_gap, max_gap);

    if (segments_.empty()) {
        segments_                 = std::move(next.segments_);
        segments_.front().gap_min = 0;
        segments_.front().gap_max = 0;
    } else {
        auto incoming            = std::move(next.segments_);
        incoming.front().gap_min = min_gap;
        incoming.front().gap_max = max_gap;
        segments_.insert(
            segments_.end(),
            std::make_move_iterator(incoming.begin()),
            std::make_move_iterator(incoming.end())
        );
    }
    pending_gap_min_ = 0;
    pending_gap_max_ = 64;
    return *this;
}

Pattern& Pattern::then(std::string_view signature, std::size_t gap_min, std::size_t gap_max) {
    auto parsed = parse(signature);
    if (!parsed) {
        if (error_.ok()) error_ = parsed.error();
        return *this;
    }
    return then(std::move(*parsed), gap_min, gap_max);
}

Pattern& Pattern::then(std::span<const std::uint8_t> bytes, std::size_t gap_min, std::size_t gap_max) {
    auto parsed = from_bytes(bytes);
    if (!parsed) {
        if (error_.ok()) error_ = parsed.error();
        return *this;
    }
    return then(std::move(*parsed), gap_min, gap_max);
}

Pattern& Pattern::within(std::size_t gap_min, std::size_t gap_max) {
    if (gap_min > gap_max) std::swap(gap_min, gap_max);
    pending_gap_min_ = gap_min;
    pending_gap_max_ = gap_max;
    return *this;
}

Pattern& Pattern::named(std::string name) & {
    name_ = std::move(name);
    return *this;
}

Pattern&& Pattern::named(std::string name) && {
    name_ = std::move(name);
    return std::move(*this);
}

bool Pattern::empty() const noexcept { return segments_.empty() || segments_.front().empty(); }

std::size_t Pattern::size() const noexcept { return segments_.empty() ? 0 : segments_.front().size(); }

std::size_t Pattern::min_size() const noexcept {
    if (segments_.empty()) return 0;
    std::size_t total = segments_.front().size();
    for (std::size_t i = 1; i < segments_.size(); ++i) {
        total = saturated_add(saturated_add(total, segments_[i].gap_min), segments_[i].size());
    }
    return total;
}

std::size_t Pattern::max_size() const noexcept {
    if (segments_.empty()) return 0;
    std::size_t total = segments_.front().size();
    for (std::size_t i = 1; i < segments_.size(); ++i) {
        total = saturated_add(saturated_add(total, segments_[i].gap_max), segments_[i].size());
    }
    return total;
}

bool Pattern::matches(const std::byte* address) const noexcept {
    return error_.ok() && address && verify_at(*this, address);
}

std::optional<std::byte*> Pattern::find_first(Range range, std::size_t alignment) const {
    if (!error_.ok() || empty() || range.empty()) return std::nullopt;
    if (alignment == 0) alignment = 1;

    const auto& first = segments_.front();
    if (first.size() > range.size()) return std::nullopt;

    const std::byte* search = range.begin;
    while (search < range.end) {
        const std::byte* candidate = find_segment(first, search, range.end);
        if (!candidate) break;
        const auto offset = static_cast<std::size_t>(candidate - range.begin);
        if (offset % alignment == 0) {
            int budget = 8192;
            if (verify_chain(*this, 1, candidate, range.begin, range.end, budget)) {
                return const_cast<std::byte*>(candidate);
            }
        }
        search = candidate + 1;
    }
    return std::nullopt;
}

std::vector<std::byte*> Pattern::find_all(Range range, std::size_t alignment, std::size_t limit) const {
    std::vector<std::byte*> matches;
    if (empty() || range.empty()) return matches;
    if (alignment == 0) alignment = 1;
    std::byte* cursor = range.begin;
    while (cursor < range.end) {
        const auto found = find_first({cursor, range.end}, alignment);
        if (!found) break;
        matches.push_back(*found);
        if (limit != 0 && matches.size() >= limit) break;
        // Every subsequent subrange must retain the original alignment phase.
        if (static_cast<std::size_t>(range.end - *found) <= alignment) break;
        cursor = *found + alignment;
    }
    return matches;
}

std::string Pattern::to_string() const {
    std::string out;
    for (std::size_t i = 0; i < segments_.size(); ++i) {
        if (i) {
            out += " +";
            out += std::to_string(segments_[i].gap_min);
            out += "..";
            out += std::to_string(segments_[i].gap_max);
            out += " ";
        }
        out += format_segment(segments_[i]);
    }
    return out;
}

} // namespace ipatch
