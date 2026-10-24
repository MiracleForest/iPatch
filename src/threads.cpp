// SPDX-License-Identifier: MIT
#include "threads.hpp"

#include <string>

#include "ipatch/error.hpp"

namespace ipatch::detail {

ThreadFreezer::~ThreadFreezer() { thaw(); }

Status ThreadFreezer::freeze() {
    if (!enabled_ || frozen_) return success();
    frozen_ = true;

    const DWORD process_id     = ::GetCurrentProcessId();
    const DWORD current_thread = ::GetCurrentThreadId();

    const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        frozen_ = false;
        return fail(
            ErrorCode::thread_suspend_failed,
            "CreateToolhelp32Snapshot failed: " + win32_message(::GetLastError())
        );
    }
    auto snapshot_handle = make_handle(snapshot);

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!::Thread32First(snapshot_handle.get(), &entry)) {
        frozen_ = false;
        return fail(ErrorCode::thread_suspend_failed, "Thread32First failed: " + win32_message(::GetLastError()));
    }

    do {
        if (entry.th32OwnerProcessID != process_id || entry.th32ThreadID == current_thread) {
            continue;
        }

        const HANDLE thread = ::OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
            FALSE,
            entry.th32ThreadID
        );
        if (!thread) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_INVALID_PARAMETER) continue; // thread exited
            thaw();
            return fail(
                ErrorCode::thread_suspend_failed,
                "OpenThread(" + std::to_string(entry.th32ThreadID) + ") failed: " + win32_message(error)
            );
        }

        if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
            const DWORD error = ::GetLastError();
            ::CloseHandle(thread);
            if (error == ERROR_INVALID_HANDLE || error == ERROR_INVALID_PARAMETER) continue;
            thaw();
            return fail(
                ErrorCode::thread_suspend_failed,
                "SuspendThread(" + std::to_string(entry.th32ThreadID) + ") failed: " + win32_message(error)
            );
        }

        ThreadEntry info;
        info.handle               = thread;
        info.id                   = entry.th32ThreadID;
        info.context.ContextFlags = CONTEXT_CONTROL;
        info.context_valid        = ::GetThreadContext(thread, &info.context) != FALSE;
        threads_.push_back(info);
    } while (::Thread32Next(snapshot_handle.get(), &entry));

    return success();
}

bool ThreadFreezer::any_rip_in(std::span<const Range> ranges) const noexcept {
    for (const auto& thread : threads_) {
        if (!thread.context_valid) continue;
        const auto rip = reinterpret_cast<const void*>(thread.context.Rip);
        for (const auto& range : ranges) {
            if (range.contains(rip)) return true;
        }
    }
    return false;
}

Status ThreadFreezer::remap_rips(std::span<const RipRemap> remaps) {
    if (!enabled_ || !frozen_ || remaps.empty()) return success();

    for (auto& thread : threads_) {
        if (!thread.context_valid) continue;
        const auto rip = static_cast<std::uintptr_t>(thread.context.Rip);
        for (const auto& remap : remaps) {
            if (!remap.maps(rip)) continue;
            thread.context.Rip =
                static_cast<DWORD64>(remap.new_begin + (rip - remap.old_begin) + remap.old_to_new_delta);
            if (!::SetThreadContext(thread.handle, &thread.context)) {
                return fail(
                    ErrorCode::thread_suspend_failed,
                    "SetThreadContext(" + std::to_string(thread.id) + ") failed: " + win32_message(::GetLastError())
                );
            }
            break;
        }
    }
    return success();
}

void ThreadFreezer::thaw() noexcept {
    for (auto& thread : threads_) {
        if (thread.handle) {
            ::ResumeThread(thread.handle);
            ::CloseHandle(thread.handle);
            thread.handle = nullptr;
        }
    }
    threads_.clear();
    frozen_ = false;
}

} // namespace ipatch::detail
