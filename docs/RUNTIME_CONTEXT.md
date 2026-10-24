# Runtime 回调与类型化上下文

`Patcher::runtime()` 在补丁点执行回调，再执行被覆盖的原始指令。回调接收 `CpuContext&`，可修改通用寄存器、XMM、标志位和目标栈内存。它保存的是补丁点的运行时状态，不是回调自身的 C++ 栈帧。

## 常用写法

```cpp
using namespace ipatch;
using namespace ipatch::x64;

auto patch = Patch::at(site).runtime([](CpuContext& ctx) noexcept {
    // 目标函数的局部变量，无需 reinterpret_cast。
    ctx.local<int>(rbp - 0x20) = 42;
    ctx.local<float>(rsp + 0x30) = 1.5f;

    // RBX 存储对象指针；返回 MyObject*。
    auto* object = ctx.as<MyObject>(rbx);
    object->field = 42;

    // 直接写 xmm3，无需记数组索引或把 byte 数组强转成 float*。
    float speed = ctx.get<float>(xmm3);
    ctx.set(xmm3, speed * 2.0f);
}).apply();
```

偏移和类型需要根据补丁点的机器码确定。优化后的局部变量可能在栈上、通用寄存器中、XMM 中，或者已被优化掉。库不能凭源码变量名自动识别它们。

## 局部变量、指针和字段

| 存储位置 | 用法 |
| --- | --- |
| `[RSP+0x20]` 中的 int | `ctx.local<int>(rsp + 0x20)` |
| `[RBP-0x18]` 中的 float | `ctx.local<float>(rbp - 0x18)` |
| `[RBP-0x20]` 中存储的对象指针 | `ctx.local<MyObject*>(rbp - 0x20)->field` |
| RBX 寄存器本身存储对象地址 | `ctx.as<MyObject>(rbx)->field` |
| `[RBX+0x18]` 中的字段 | `ctx.local<int>(rbx + 0x18)` |
| 未对齐或仅已知字节布局的内存 | `ctx.get<float>(rbp - 0x13)` / `ctx.set(rbp - 0x13, 1.0f)` |

`local<T>(operand)` 返回 `T&`，因此支持赋值、`+=` 和成员访问。const 上下文返回 `const T&`；`as<T>(reg)` 同样传播 const。引用访问要求那里确实存在正确类型且正确对齐的对象。

`get<T>(operand)` 返回值副本，`set(operand, value)` 写回值。它们通过字节复制实现，避免未对齐的类型化解引用，也不会向 XMM 的 byte 数组强行构造浮点引用。`set` 根据 value 推导类型，例如 `1.0f` 是四字节 float，`1.0` 是八字节 double；需要时可写 `ctx.set<float>(rsp + 0x20, 1.0f)` 明确类型。

地址基于捕获的寄存器实时计算。修改 `ctx.rsp` / `ctx.rbp` 后，再访问相关位置会使用新值。默认无操作数宽度限制；显式 `mem(rbp, -0x20, 4)` 要求读写的 T 恰好占四字节。

旧接口继续支持：

```cpp
ctx.local<int>(0x20) = 42;        // 默认 RSP 相对偏移
ctx.local<0x20, int>() = 42;
ctx.offset<int, 0x20>() = 42;
auto* slot = ctx.stack_at<int>(0x20);
auto* object = ctx.as<MyObject>(ctx.rbx);
```

## XMM 标量与向量

`x64::xmm0` 到 `x64::xmm15` 是专门的上下文选择器，与通用寄存器类型分开，不会误用通用寄存器编号。未引入 `using namespace ipatch::x64` 时写 `ctx.get<float>(ipatch::x64::xmm3)`。

```cpp
float a = ctx.get<float>(xmm3);          // 最低 32 位
double b = ctx.get<double>(xmm3);        // 最低 64 位
ctx.set(xmm3, 2.5f);                    // 只改最低 32 位

float z = ctx.get<float, 2>(xmm3);       // 第三个 float lane，编号从 0 开始
ctx.set<float, 2>(xmm3, z * 2.0f);
ctx.set<double, 1>(xmm15, 9.0);          // 高 64 位

auto vector = ctx.get<std::array<float, 4>>(xmm3);
vector[1] += 1.0f;
ctx.set(xmm3, vector);                  // 写完整 128 位
```

Lane 单位是 `sizeof(T)`，其边界在编译期检查。写一个 lane 保留寄存器其他字节，这与某些 SIMD 指令清零高位的行为不同。`get` / `set` 是位模式读取和写入，不进行整数与浮点的数值转换。原有 `ctx.xmm[index]` 字节数组保留；这里仅覆盖 XMM 的 128 位，不包含 YMM / ZMM 的高位。

## 通用寄存器

原有 `ctx.rax` 等字段可以继续直接访问，也可以统一用选择器：

```cpp
auto count = ctx.get<std::uint32_t>(eax);
ctx.set(eax, std::uint32_t{42});         // 写 EAX 会将 RAX 的高 32 位清零
ctx.set(ax, std::uint16_t{7});           // 写 AX 保留其余 48 位
ctx.set(al, std::uint8_t{1});            // 写 AL 保留其余 56 位

auto* object = ctx.get<MyObject*>(rbx);  // 同样无需强转
ctx.set(rbx, object);
```

类型宽度必须匹配寄存器宽度；读取 64 位 RAX 应使用 `std::uint64_t`，不能用四字节 `int`。只有有限的 trivial-copy 类型可用于值访问。无效 ID、通配寄存器、错误的宽度和溢出的内存操作数属于编程错误，在 noexcept 回调中会终止进程，避免静默访问错误状态。选择器检查不会验证目标内存的映射、对象类型或生命周期。

## 回调执行与生命周期

捕获式 lambda 由 Patch 持有，恢复或销毁补丁后释放；引用捕获的对象仍需调用者保证有效。回调必须 `noexcept`，异常不能穿过生成的机器码。Patch 句柄离开作用域时自动恢复，因此应保留它直到不再需要回调。

生成的 thunk 在修改栈之前保存原始标志位，按 Windows x64 ABI 为 C++ 回调对齐栈并预留 shadow space。`ctx.rsp` 仍指向目标在补丁点的原始栈顶。`ctx.rip` 初始指向跳板中的原始指令副本；回调后的原指令若写同一寄存器，会覆盖回调的改动，需相应选择插入位置。

Runtime 只接受足以放置入口跳转的完整、可位置无关复制的指令；RIP 相对操作数及相对跳转 / 调用会被拒绝，需要显式设计 `springboard()`。局部变量访问和对象指针访问不承担自动探测非法内存的职责。

[运行示例](../examples/runtime_context.cpp) 在真实生成代码中同时修改 RBP 局部变量和 XMM3，输出 `before: 9, patched: 48, restored: 9`。专项测试位于 [test_context.cpp](../tests/test_context.cpp)，覆盖类型读写、所有通用寄存器映射、XMM lane、原有 API、实际执行恢复、标志位和栈对齐。

本次只增加访问方法和独立寄存器选择器，`CpuContext` 数据成员及布局保持不变。布局断言同时保护 `offsetof(CpuContext, xmm) == 144` 和 `sizeof(CpuContext) == 400`。
