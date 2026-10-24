// SPDX-License-Identifier: MIT
#pragma once

// iPatch is Windows x86-64 only. Failing early here is much friendlier than
// producing a library that silently corrupts a 32-bit process.
#if !defined(_WIN32)
#error "iPatch only supports Windows."
#endif
#if !defined(_M_X64) && !defined(__x86_64__)
#error "iPatch only supports the x86-64 architecture."
#endif

#if defined(IPATCH_SHARED)
#if defined(IPATCH_BUILDING)
#define IPATCH_API __declspec(dllexport)
#else
#define IPATCH_API __declspec(dllimport)
#endif
#else
#define IPATCH_API
#endif

#if defined(_MSC_VER)
#define IPATCH_MSVC 1
#else
#define IPATCH_MSVC 0
#endif

// The private machine-code backend is Xbyak 7.43. It is vendored as a
// header-only dependency, so consumers only link iPatch itself.

#define IPATCH_VERSION_MAJOR 0
#define IPATCH_VERSION_MINOR 2
#define IPATCH_VERSION_PATCH 0
#define IPATCH_VERSION_STRING "0.2.0"
