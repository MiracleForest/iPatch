// SPDX-License-Identifier: MIT
#include "ipatch/module.hpp"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#include "win.hpp"

namespace ipatch {
namespace {

[[nodiscard]] std::string to_utf8(const wchar_t* text) {
    if (!text) return {};
    const int length = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) return {};
    std::string out(static_cast<std::size_t>(length - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), length, nullptr, nullptr);
    return out;
}

[[nodiscard]] std::wstring to_wide(std::string_view text) {
    if (text.empty()) return {};
    const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        // Fall back to the ANSI code page for callers passing non-UTF-8 names.
        const int ansi_length =
            ::MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (ansi_length <= 0) return {};
        std::wstring out(static_cast<std::size_t>(ansi_length), L'\0');
        ::MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()), out.data(), ansi_length);
        return out;
    }
    std::wstring out(static_cast<std::size_t>(length), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length);
    return out;
}

[[nodiscard]] bool equals_ascii_ci(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        wchar_t ca = a[i];
        wchar_t cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = static_cast<wchar_t>(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = static_cast<wchar_t>(cb - L'A' + L'a');
        if (ca != cb) return false;
    }
    return true;
}

[[nodiscard]] bool is_valid_image(std::byte* base) noexcept {
    if (!base) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const std::byte*>(base) + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

} // namespace

bool Section::executable() const noexcept { return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; }

bool Section::readable() const noexcept { return (characteristics & IMAGE_SCN_MEM_READ) != 0; }

bool Section::writable() const noexcept { return (characteristics & IMAGE_SCN_MEM_WRITE) != 0; }

Result<Module> module_from_handle(void* handle) {
    if (!handle) {
        return fail(ErrorCode::invalid_argument, "module handle is null");
    }
    auto* base = reinterpret_cast<std::byte*>(handle);
    if (!is_valid_image(base)) {
        return fail(ErrorCode::invalid_argument, "handle does not point to a valid PE image");
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

    Module module;
    module.handle_ = handle;
    module.base_   = base;
    module.size_   = nt->OptionalHeader.SizeOfImage;
    return module;
}

Module Module::main() noexcept {
    auto result = module_from_handle(::GetModuleHandleW(nullptr));
    return result ? *result : Module{};
}

Result<Module> Module::find(std::string_view name) {
    if (name.empty()) return fail(ErrorCode::invalid_argument, "module name is empty");

    const std::wstring wide = to_wide(name);
    if (wide.empty()) return fail(ErrorCode::invalid_argument, "module name is not valid text");

    const auto   process_id = ::GetCurrentProcessId();
    const HANDLE snapshot   = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return fail(
            ErrorCode::module_not_found,
            "CreateToolhelp32Snapshot failed: " + detail::win32_message(::GetLastError())
        );
    }
    auto handle = detail::make_handle(snapshot);

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Module32FirstW(handle.get(), &entry)) {
        return fail(ErrorCode::module_not_found, "no modules found");
    }

    const bool wants_path = wide.find(L'\\') != std::wstring::npos || wide.find(L'/') != std::wstring::npos;
    do {
        const std::wstring_view module_name{entry.szModule};
        const std::wstring_view module_path{entry.szExePath};
        const bool matched = wants_path ? equals_ascii_ci(module_path, wide) : equals_ascii_ci(module_name, wide);
        if (matched) {
            return module_from_handle(entry.hModule);
        }
    } while (::Module32NextW(handle.get(), &entry));

    return fail(ErrorCode::module_not_found, std::string(name));
}

Result<Module> Module::containing(const void* address) {
    if (!address) return fail(ErrorCode::invalid_argument, "address is null");

    HMODULE handle = nullptr;
    if (!::GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &handle
        )
        || !handle) {
        return fail(ErrorCode::module_not_found, "address is not inside a loaded module");
    }
    return module_from_handle(handle);
}

std::string Module::path() const {
    if (!valid()) return {};
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length =
            ::GetModuleFileNameW(static_cast<HMODULE>(handle_), buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size()) {
            buffer.resize(length);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    return to_utf8(buffer.c_str());
}

std::string Module::name() const {
    const std::string full = path();
    const auto        pos  = full.find_last_of("\\/");
    return pos == std::string::npos ? full : full.substr(pos + 1);
}

std::vector<Section> Module::sections() const {
    std::vector<Section> result;
    if (!valid()) return result;

    const auto*       dos     = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    const auto*       nt      = reinterpret_cast<const IMAGE_NT_HEADERS*>(base_ + dos->e_lfanew);
    const auto*       section = IMAGE_FIRST_SECTION(nt);
    const std::size_t count   = nt->FileHeader.NumberOfSections;

    for (std::size_t i = 0; i < count; ++i, ++section) {
        char name_buffer[9]{};
        std::memcpy(name_buffer, section->Name, 8);
        Section info;
        info.name            = name_buffer;
        info.characteristics = section->Characteristics;

        const std::size_t rva    = section->VirtualAddress;
        std::size_t       length = section->Misc.VirtualSize;
        if (length == 0) length = section->SizeOfRawData;
        if (rva >= size_) continue;
        length     = std::min(length, size_ - rva);
        info.range = {base_ + rva, base_ + rva + length};
        result.push_back(std::move(info));
    }
    return result;
}

Range Module::executable_range() const {
    Range result{};
    for (const auto& section : sections()) {
        if (!section.executable() || section.range.empty()) continue;
        if (!result.begin || section.range.begin < result.begin) result.begin = section.range.begin;
        if (!result.end || section.range.end > result.end) result.end = section.range.end;
    }
    return result.begin ? result : range();
}

Result<Range> Module::section(std::string_view name) const {
    if (!valid()) return fail(ErrorCode::module_not_found, "module is not valid");
    for (const auto& info : sections()) {
        if (info.name == name) return info.range;
    }
    // Section names are ASCII; use a case-insensitive comparison for ".TEXT".
    for (const auto& info : sections()) {
        if (info.name.size() != name.size()) continue;
        bool equal = true;
        for (std::size_t i = 0; i < name.size(); ++i) {
            char a = info.name[i];
            char b = name[i];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
            if (a != b) {
                equal = false;
                break;
            }
        }
        if (equal) return info.range;
    }
    return fail(ErrorCode::not_found, "section not found: " + std::string(name));
}

Result<Range> Module::text() const { return section(".text"); }

} // namespace ipatch
