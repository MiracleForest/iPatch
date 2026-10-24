// SPDX-License-Identifier: MIT
#include "ipatch/scan.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include "address.hpp"
#include "memory.hpp"
#include "win.hpp"

namespace ipatch {

Status MatchResult::check_borrow(std::size_t size, std::size_t alignment, bool writable) const {
    if (!value_) return std::unexpected(value_.error());
    if (reinterpret_cast<std::uintptr_t>(*value_) % alignment != 0)
        return fail(ErrorCode::invalid_argument, "ptr/ref: address is not aligned for T; use read<T>() for a copy");
    if (writable ? !detail::is_writable(*value_, size) : !detail::is_readable(*value_, size))
        return fail(
            ErrorCode::access_denied,
            writable ? "ptr/ref: range is not readable and writable; use const T for read-only access"
                     : "ptr/ref: range is not readable"
        );
    return success();
}

Status MatchResult::copy_to(std::span<std::byte> output) const {
    if (!value_) return std::unexpected(value_.error());
    if (!detail::is_readable(*value_, output.size()))
        return fail(ErrorCode::access_denied, "read: range is not readable");
    std::memcpy(output.data(), *value_, output.size());
    return success();
}

MatchResult MatchResult::offset(std::ptrdiff_t bytes) const {
    if (!value_) return *this;
    return MatchResult(detail::offset_address(*value_, bytes));
}

MatchResult MatchResult::rel32(std::ptrdiff_t displacement_offset, std::ptrdiff_t next_instruction_offset) const {
    if (!value_) return *this;
    auto displacement = offset(displacement_offset);
    if (!displacement) return displacement;
    auto data = detail::read_memory(displacement.address(), sizeof(std::int32_t));
    if (!data) return MatchResult(data.error());
    std::int32_t relative{};
    std::memcpy(&relative, data->data(), sizeof(relative));
    return offset(next_instruction_offset).offset(relative);
}

Result<std::uintptr_t> MatchResult::rva(const Module& module) const {
    if (!value_) return std::unexpected(value_.error());
    if (!module.valid()) return fail(ErrorCode::module_not_found, "module is not valid");
    const auto address = reinterpret_cast<std::uintptr_t>(*value_);
    const auto base    = reinterpret_cast<std::uintptr_t>(module.base());
    if (address < base || address - base >= module.size())
        return fail(ErrorCode::out_of_range, "address is outside the module");
    return address - base;
}

ScanQuery::ScanQuery(Pattern pattern) { add(std::move(pattern)); }

ScanQuery::ScanQuery(std::string_view signature) { add(signature); }

ScanQuery& ScanQuery::add(Pattern pattern) {
    if (!pattern.error().ok()) {
        if (error_.ok()) error_ = pattern.error();
        return *this;
    }
    if (pattern.empty()) {
        if (error_.ok()) error_ = Error{ErrorCode::invalid_pattern, "empty pattern"};
        return *this;
    }
    patterns_.push_back(std::move(pattern));
    return *this;
}

ScanQuery& ScanQuery::add(std::string_view signature) {
    auto parsed = Pattern::parse(signature);
    if (!parsed) {
        if (error_.ok()) error_ = parsed.error();
        return *this;
    }
    return add(std::move(*parsed));
}

ScanQuery& ScanQuery::add(std::initializer_list<std::string_view> signatures) {
    for (auto signature : signatures) add(signature);
    return *this;
}

ScanQuery& ScanQuery::add(PatternSet patterns) {
    for (auto& pattern : patterns) add(std::move(pattern));
    return *this;
}

ScanQuery& ScanQuery::add(std::initializer_list<Pattern> patterns) {
    for (const auto& pattern : patterns) add(pattern);
    return *this;
}

ScanQuery& ScanQuery::in(Range range) {
    if (range.empty()) {
        if (error_.ok()) error_ = Error{ErrorCode::invalid_argument, "scan range is empty"};
    } else ranges_.push_back(range);
    return *this;
}

ScanQuery& ScanQuery::in(Module module) {
    if (!module.valid()) {
        if (error_.ok()) error_ = Error{ErrorCode::module_not_found, "scan module is invalid"};
    } else modules_.push_back(std::move(module));
    return *this;
}

ScanQuery& ScanQuery::in_main_module() {
    auto main_module = Module::main();
    if (main_module.valid()) modules_.push_back(std::move(main_module));
    else if (error_.ok()) error_ = Error{ErrorCode::module_not_found, "main module is unavailable"};
    return *this;
}

ScanQuery& ScanQuery::in_process(bool enabled) {
    process_ = enabled;
    return *this;
}

ScanQuery& ScanQuery::executable_only(bool enabled) {
    executable_only_ = enabled;
    return *this;
}

ScanQuery& ScanQuery::alignment(std::size_t alignment) {
    if (alignment == 0) alignment = 1;
    alignment_ = alignment;
    return *this;
}

ScanQuery& ScanQuery::limit(std::size_t count) {
    limit_ = count;
    return *this;
}

Result<std::vector<Range>> ScanQuery::resolve_ranges() const {
    std::vector<Range> ranges = ranges_;

    // Default scope uses section boundaries too; an enclosing executable_range
    // can include data or inaccessible gaps between separate code sections.
    if (ranges_.empty() && modules_.empty() && !process_) {
        auto query = *this;
        query.in_main_module();
        if (!query.error_.ok()) return std::unexpected(query.error_);
        return query.resolve_ranges();
    }

    for (const auto& module : modules_) {
        const auto sections = module.sections();
        for (const auto& section : sections) {
            if (section.range.empty()) continue;
            if (executable_only_ && !section.executable()) continue;
            if (!executable_only_ && !section.readable()) continue;
            ranges.push_back(section.range);
        }
    }

    if (process_) {
        SYSTEM_INFO system_info{};
        ::GetSystemInfo(&system_info);
        auto       cursor  = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
        const auto maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);
        while (cursor < maximum) {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQuery(reinterpret_cast<void*>(cursor), &info, sizeof(info)) == 0) break;
            const auto base        = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
            const auto region_size = static_cast<std::uintptr_t>(info.RegionSize);
            if (region_size == 0) break;
            const auto end = base + region_size;
            if (info.State == MEM_COMMIT && (info.Protect & PAGE_GUARD) == 0 && (info.Protect & PAGE_NOACCESS) == 0) {
                const bool executable =
                    (info.Protect
                     & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    != 0;
                const bool readable = (info.Protect
                                       & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ
                                          | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                                   != 0;
                if (readable && (!executable_only_ || executable)) {
                    ranges.push_back({reinterpret_cast<std::byte*>(base), reinterpret_cast<std::byte*>(end)});
                }
            }
            const auto next = end;
            if (next <= cursor) break;
            cursor = next;
        }
    }

    std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) { return a.begin < b.begin; });
    std::vector<Range> merged;
    for (const auto& range : ranges) {
        if (range.empty()) continue;
        if (!merged.empty() && range.begin <= merged.back().end) {
            if (range.end > merged.back().end) merged.back().end = range.end;
        } else {
            merged.push_back(range);
        }
    }
    for (const auto& range : merged) {
        if (!detail::is_readable(range.begin, range.size()))
            return fail(ErrorCode::access_denied, "scan range contains unreadable memory");
    }
    return merged;
}

Result<std::vector<Match>> ScanQuery::scan_ranges(const std::vector<Range>& ranges, std::size_t stop_after) const {
    std::vector<Match> matches;
    for (std::size_t pattern_index = 0; pattern_index < patterns_.size(); ++pattern_index) {
        const auto& pattern = patterns_[pattern_index];
        for (const auto& range : ranges) {
            const std::size_t remaining =
                stop_after == 0 ? 0 : (matches.size() >= stop_after ? 0 : stop_after - matches.size());
            if (stop_after != 0 && remaining == 0) break;
            for (auto* address : pattern.find_all(range, alignment_, remaining)) {
                matches.push_back(Match{address, pattern_index, pattern.name()});
                if (stop_after != 0 && matches.size() >= stop_after) break;
            }
        }
    }

    std::sort(matches.begin(), matches.end(), [](const Match& a, const Match& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.pattern_index < b.pattern_index;
    });
    // A bounded internal scan (used by require_unique) must see the second
    // match even when the caller set limit(1) for all().
    if (stop_after == 0 && limit_ != 0 && matches.size() > limit_) {
        matches.resize(limit_);
    }
    return matches;
}

Result<std::vector<Match>> ScanQuery::all() const {
    if (!error_.ok()) return std::unexpected(error_);
    if (patterns_.empty()) {
        return fail(ErrorCode::invalid_argument, "scan query has no patterns");
    }
    auto ranges = resolve_ranges();
    if (!ranges) return std::unexpected(ranges.error());
    return scan_ranges(*ranges, 0);
}

MatchResult ScanQuery::first() const {
    auto result = require_first();
    return result ? MatchResult(result->address) : MatchResult(result.error());
}

Result<Match> ScanQuery::require_first() const {
    if (!error_.ok()) return std::unexpected(error_);
    if (patterns_.empty()) {
        return fail(ErrorCode::invalid_argument, "scan query has no patterns");
    }
    auto ranges = resolve_ranges();
    if (!ranges) return std::unexpected(ranges.error());

    Match best{};
    for (std::size_t pattern_index = 0; pattern_index < patterns_.size(); ++pattern_index) {
        const auto& pattern = patterns_[pattern_index];
        for (const auto& range : *ranges) {
            const auto found = pattern.find_first(range, alignment_);
            if (!found) continue;
            if (!best.address || *found < best.address) {
                best = Match{*found, pattern_index, pattern.name()};
            }
        }
    }
    if (!best.address) return fail(ErrorCode::not_found, "pattern not found");
    return best;
}

MatchResult ScanQuery::unique() const {
    auto result = require_unique();
    return result ? MatchResult(result->address) : MatchResult(result.error());
}

Result<Match> ScanQuery::require_unique() const {
    if (!error_.ok()) return std::unexpected(error_);
    if (patterns_.empty()) {
        return fail(ErrorCode::invalid_argument, "scan query has no patterns");
    }
    auto ranges = resolve_ranges();
    if (!ranges) return std::unexpected(ranges.error());

    // Two matches are enough to prove ambiguity. This bounded scan also
    // bypasses limit(), so a caller's limit(1) cannot hide a duplicate.
    auto matches = scan_ranges(*ranges, 2);
    if (!matches) return std::unexpected(matches.error());
    if (matches->empty()) {
        return fail(ErrorCode::not_found, "signature not found");
    }
    if (matches->size() > 1) {
        return fail(ErrorCode::ambiguous, "signature matched at least two times; use a more specific signature");
    }
    return matches->front();
}

ScanQuery scan(Pattern pattern) { return ScanQuery(std::move(pattern)); }

ScanQuery scan(std::string_view signature) { return ScanQuery(signature); }

ScanQuery scan(std::initializer_list<std::string_view> signatures) {
    ScanQuery query;
    query.add(signatures);
    return query;
}

Result<std::byte*> locate(Range range, std::string_view signature, std::ptrdiff_t offset) {
    if (range.empty()) {
        return fail(ErrorCode::invalid_argument, "locate range is empty");
    }
    return ScanQuery(signature).in(range).unique().offset(offset).raw();
}

Result<std::byte*> locate(const Module& module, std::string_view signature, std::ptrdiff_t offset) {
    if (!module.valid()) {
        return fail(ErrorCode::module_not_found, "cannot locate a signature in an invalid module");
    }
    return ScanQuery(signature).in(module).unique().offset(offset).raw();
}

namespace {
template <typename Text>
ScanQuery text_query(Text text, bool null_terminated) {
    auto pattern = Pattern::from_string(text, null_terminated);
    // Preserve invalid_pattern through the existing query error mechanism.
    ScanQuery query = pattern ? ScanQuery(std::move(*pattern)) : ScanQuery(Pattern{});
    query.executable_only(false);
    return query;
}
} // namespace

ScanQuery scan_string(std::string_view text, bool null_terminated) { return text_query(text, null_terminated); }

ScanQuery scan_string(std::u16string_view text, bool null_terminated) { return text_query(text, null_terminated); }

Result<std::byte*> locate_string(Range range, std::string_view text, std::ptrdiff_t offset, bool null_terminated) {
    return scan_string(text, null_terminated).in(range).unique().offset(offset).raw();
}

Result<std::byte*> locate_string(Range range, std::u16string_view text, std::ptrdiff_t offset, bool null_terminated) {
    return scan_string(text, null_terminated).in(range).unique().offset(offset).raw();
}

Result<std::byte*> locate_string(
    const Module&    module,
    std::string_view text,
    std::ptrdiff_t   offset,
    bool             null_terminated
) {
    return scan_string(text, null_terminated).in(module).unique().offset(offset).raw();
}

Result<std::byte*> locate_string(
    const Module&       module,
    std::u16string_view text,
    std::ptrdiff_t      offset,
    bool                null_terminated
) {
    return scan_string(text, null_terminated).in(module).unique().offset(offset).raw();
}

} // namespace ipatch
