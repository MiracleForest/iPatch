# Patch 与 Hook 回调

## 生命周期

`Patch` 默认是作用域对象，析构时恢复原字节并释放 relay/trampoline。需要让补丁
一直生效时，可以直接提交为永久补丁：

```cpp
auto patch = ipatch::Patch::apply_permanent([&](ipatch::Patcher& p) {
    p.at(target).expect({0x90}).nop();
});
```

也可以在提交后调用 `patch->make_permanent()` 或 `patch->detach()`。永久补丁的
可执行分配会保留到进程结束，因此目标入口不会跳到已释放的 relay。句柄仍然存活时
可以显式调用 `restore()`；恢复成功后 relay 会立即释放。

## Patch 构建回调

`Patch::apply(callback)` 和 `Patch::apply_permanent(callback)` 会同步创建一个
`Patcher` 并把它传给回调。这里捕获的是“构建补丁的代码”的局部变量；回调不会在
目标函数运行时执行，也不会自动获得目标函数的栈帧：

```cpp
int replacement = 7;
auto patch = ipatch::Patch::apply([&](ipatch::Patcher& p) {
    p.at(site).write({static_cast<std::uint8_t>(replacement)});
});
```

回调只在构建和提交期间执行，不会被库保存到异步任务中。

## Lambda Hook

无捕获 lambda 可以直接作为 detour：

```cpp
auto hook = ipatch::Hook::create(target, [](int value) { return value + 100; });
```

捕获 lambda 使用显式签名版本。库会生成 Windows x64 thunk，保存 RCX/RDX/R8/R9
和 XMM0-XMM3，然后调用捕获对象：

```cpp
int bias = 100;
auto hook = ipatch::Hook::create_typed<int(int)>(target, [bias](int value) {
    return value + bias;
});
```

`Signature` 必须和目标的实际 ABI 完全一致。被优化的内部函数、非标准调用约定或
无法确认参数布局的入口应使用原始 `void*` Hook，并由调用者提供寄存器级适配。这个
接口不会把任意 C++ lambda 宣称为通用 ABI 安全回调。

## Runtime patch callbacks

`Patcher::runtime()` also accepts a `noexcept` callable with a `CpuContext&`
parameter. Capturing callables are retained by the active `Patch`, so a local
capture can be used while the target executes:

```cpp
const int replacement = 42;
auto patch = ipatch::Patch::at(site).runtime(
    [replacement](ipatch::CpuContext& context) noexcept {
        context.local<0x20, int>() = replacement;
    }).apply();
```

Use `context.local<T>(offset)`, `context.local<offset, T>()`, or the equivalent
`offset<T>(offset)` helpers to access a stack slot relative to the target's
original `RSP`. The offset must be confirmed from disassembly; compiler
optimisation can keep a source local in a register or eliminate it.

`CpuContext::as<T>(value)` is a shorthand for converting a captured pointer-sized
register to `T*`, for example `context.as<Player>(context.rbx)`.
