# iPatch

Windows x86-64 / C++23 链式补丁与内联 Hook 库。

提供特征码和文本搜索、地址偏移、RIP 相对地址解析、事务写入、自动跳板、Hook trampoline，以及 RAII 恢复。写入编码使用私有内置的 Xbyak 7.43，使用者只需包含 `<ipatch/ipatch.hpp>`。

## 搜索字符串与偏移

`scan("48 8B ??")` 解析十六进制特征码；`scan_string("hello")` 匹配原始文本。两种入口明确区分，不会猜测输入格式。

```cpp
#include <ipatch/ipatch.hpp>
using namespace ipatch;

auto module = Module::main();

// 字符串可能位于 .rdata / .data，文本搜索默认包含可读的数据节。
auto text = scan_string("config.json", true) // true：同时匹配末尾 NUL
                .in(module)
                .unique();                  // 必须恰好匹配一次

if (!text) {
    // not_found / ambiguous / invalid_pattern / access_denied 等
    report(text.error().format());
    return;
}

auto after_prefix = text.offset(7);          // 按字节偏移，可为负数
auto rva = text.rva(module);                 // 相对模块基址，检查模块边界
```

也可以一次完成唯一定位和偏移：

```cpp
auto site = locate(module, "75 06 41 83 F8 06", 5);
auto text = locate_string(module, "mode=0", 5, true);
auto wide = locate_string(module, u"设置", 0, true); // UTF-16LE
```

这些函数返回 `Result<std::byte*>`。偏移单位始终是字节，UTF-16 中一个 code unit 占两字节。窄字符串按原始字节匹配，适用于 ASCII / UTF-8；不进行大小写折叠、编码转换或 Unicode 归一化。内嵌 NUL 可通过显式长度的 `string_view` 搜索。

## 解析相对地址

常见的 `CALL rel32`、`JMP rel32` 和 RIP 相对 `MOV/LEA` 不需要手写指针计算：

```cpp
auto callee = scan("E8 ?? ?? ?? ?? 84 C0")
                  .in(module).unique().rel32(1, 5);

auto global = scan("48 8B 05 ?? ?? ?? ??")
                  .in(module).unique().rel32(3, 7);
```

`rel32(disp_offset, next_offset)` 的两个偏移都相对当前结果地址：

```text
目标 = 当前地址 + next_offset + int32(当前地址 + disp_offset)
```

它检查位移字段的可读性和地址算术溢出。`MOV [RIP+disp32]` 返回被访问的内存地址，不会继续读取其中的指针。该接口不解码或验证指令；偏移须对应实际指令格式。字符串搜索返回字符串本身；寻找哪些指令引用了它，需要另外定位指令再解析目标。

失败会沿 `.unique().offset(...).rel32(...).rva(...)` 传播，保留最初的错误。

## 修改并自动恢复

```cpp
char buffer[] = "mode=0";
auto patch = Patch::search_string("mode=0", true)
                 .in(Range::from(buffer, sizeof(buffer)))
                 .unique()
                 .offset(5)
                 .expect({0x30})
                 .write({0x31})
                 .apply();

if (!patch) {
    report(patch.error().format());
    return;
}
// buffer 现在是 "mode=1"；patch 析构时恢复。
// 也可提前调用 patch->restore() 并检查返回值。
```

机器码修改使用相同的构建链：

```cpp
auto patch = Patch::search("75 06 41 83 F8 06")
                 .in(module).unique().offset(5)
                 .expect({0x06}).write({0x07}).apply();

// 先解析 CALL 目标，再将写入游标移动到该目标。
auto target = Patch::search("E8 ?? ?? ?? ?? 84 C0")
                  .in(module).unique().rel32(1, 5).find();
```

`unique()` 应在解析搜索结果之前调用：`write()`、`end()`、`rel32()`、跳板构建等操作都会触发解析。`offset()` / `skip()` 相对当前游标累加，写入也会推进游标。偏移检查算术溢出，不要求目标仍在原扫描范围内；实际读写时另行检查内存。

需要永久补丁时，使用 `patch->make_permanent()` 或 `Patch::apply_permanent(...)`。普通补丁必须保留返回的句柄，否则会随临时对象析构而恢复。

## 特征码与多条件搜索

```cpp
auto pattern = Pattern::parse("48 8B 05 ?? ?? ?? ??");
if (!pattern) return;
pattern->within(0, 32).then("E8 ?? ?? ?? ??");

auto found = scan(*pattern).in(module).unique();
auto alternatives = scan({"48 89 5C 24 ??", "48 83 EC ??"})
                        .in(module).limit(10).all();
```

支持完整字节、单独的 `?` / `??`、半字节通配 `4?` 和紧凑格式 `488B????????`。复合签名中的无效输入会保留错误，不会退化为只匹配前半段。

也可以通过指令构建签名：

```cpp
auto patch = Patch::search()
                 .jnz().cmp(x64::r8d, 6)
                 .in(module).unique().offset(5)
                 .write({0x07}).apply();
```

- `first()` 返回最早地址；`require_first()` 同时返回模式索引和诊断名称。
- `unique()` 返回可继续偏移的 `MatchResult`；`require_unique()` 返回 `Result<Match>`。
- `all()` 按地址和模式索引排序，包含重叠匹配。
- `limit(n)` 只限制 `all()` 的结果数量，不影响唯一性判断。
- 不同备选模式在同一地址匹配，仍计为多个结果。
- 相邻、重叠范围会合并；`alignment(n)` 以每个合并后范围的起点为基准。
- 显式空范围或无效模块会报错；只有未指定范围时才默认搜索主模块。
- 模块搜索按节属性选择范围；包含不可读内存的范围返回 `access_denied`。

## 跳板与 Hook

```cpp
// 已知模块 RVA
auto patch = Patch::at(module, 0x1234)
                 .guard_null(x64::rsi, module.at(0x5678))
                 .apply();

// 自动重定位覆盖的指令，并生成原始函数 trampoline
auto hook = Hook::create(reinterpret_cast<void*>(&target),
                         reinterpret_cast<void*>(&detour));
if (!hook) return;
auto original = hook->original<int (*)(int)>();
```

`jmp()` / `call()` 根据距离和可用空间选择直接分支或 relay / code cave。`jmp_short()` 要求目标在 rel8 范围内。`write_springboard(length, bytes)` 支持比原始范围更长的替换；`springboard(length, callback)` 可用指令 API 构建跳板。不传长度时按一条原始指令推断。

`guard_null()` 保留一条可直接复制的原指令，插入空指针判断；它会修改标志位，不支持原指令含 RIP 相对或相对控制流。普通 springboard 的原指令需要由调用者明确保留。线程冻结和恢复仍受目标代码生命周期约束，`restore()` / `remove()` 可能返回 `busy`。

## 维护与验证

Runtime 回调可直接使用寄存器名称和类型化局部变量：

```cpp
using namespace ipatch::x64;
auto patch = ipatch::Patch::at(site).runtime([](ipatch::CpuContext& ctx) noexcept {
    ctx.local<int>(rbp - 0x20) = 42;
    auto value = ctx.get<float>(xmm3);
    ctx.set(xmm3, value * 2.0f);
}).apply();
```

偏移与类型须对应目标指令的实际布局；XMM 标量写入保留其余位。可运行 `xmake run ipatch_example_runtime_context` 查看局部变量、对象指针和 XMM 一起修改的完整示例。

定位层分为三部分：`Pattern` 构建字节模式，`ScanQuery` 选择范围和匹配策略，`MatchResult` 做地址转换。文本入口复用现有模式扫描器；偏移检查集中在 `src/address.hpp`，扫描和补丁共用，不另建一套扫描实现。

- [扫描与地址接口说明](docs/SCANNING.md)
- [类型化读写、定位结果衔接和 Hook 推导](docs/WORKFLOWS.md)
- [本轮审查记录](docs/REVIEW.md)
- [可直接运行的字符串定位示例](examples/string_scan.cpp)
- [扫描回归测试](tests/test_scan.cpp)
- [回调接口](docs/CALLBACKS.md)
- [运行时上下文](docs/RUNTIME_CONTEXT.md)

扫描针对当前进程，不是远程进程读取器。扫描期间调用者需保持模块已加载、缓冲区有效且内存保护稳定；读取前检查不提供对并发卸载的同步保证。底层 `Pattern::matches(address)` 要求调用者保证最大匹配范围可读；有边界的输入优先使用 `find_first(range)` 或 `scan(...).in(range)`。

公共 C++ 类型有新增字段和方法，升级后应重新编译库与使用者，不将新旧 DLL 和头文件混用。
