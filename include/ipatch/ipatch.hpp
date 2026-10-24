// SPDX-License-Identifier: MIT
#pragma once

/// iPatch - fluent x86-64 patching and inline hooks for Windows.
///
/// Design pillars:
///   * scan -> locate -> patch as one chain
///   * every patch is a transaction with an RAII restore
///   * signatures can be raw bytes, instruction patterns, alternatives, or
///     gap-separated multi-condition chains
///   * hooks choose rel32, near relay, or short-jump springboard automatically
///
/// Typical use:
///
///     #include <ipatch/ipatch.hpp>
///     using namespace ipatch;
///
///     auto patch = Patch::search("48 8B 05 ?? ?? ?? ??")
///                      .offset(3)
///                      .jmp(&replacement)
///                      .apply();
///
///     auto hook = Hook::create("75 06 41 83 F8 06", &handler);

#include "ipatch/config.hpp"
#include "ipatch/context.hpp"
#include "ipatch/error.hpp"
#include "ipatch/hook.hpp"
#include "ipatch/module.hpp"
#include "ipatch/patch.hpp"
#include "ipatch/pattern.hpp"
#include "ipatch/range.hpp"
#include "ipatch/scan.hpp"
#include "ipatch/x64.hpp"
