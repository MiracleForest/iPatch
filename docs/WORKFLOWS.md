# 开发体验：从定位结果到修改

## 定位错误不再丢失

以前常见写法是 `Patch::at(result.value())`。失败的 `MatchResult::value()` 返回空指针，补丁最终只看到“地址为空”，无法判断原本是未找到、签名歧义还是不可读内存。

现在可以直接传入 `MatchResult` 或 `Result<std::byte*>`：

```cpp
auto site = scan("75 06 41 83 F8 06").in(module).unique().offset(5);
auto patch = Patch::at(site).expect_value(std::uint8_t{6})
                            .write_value(std::uint8_t{7}).apply();
if (!patch) report(patch.error().format());

auto other = locate(module, "48 8B 05 ?? ?? ?? ??", 3);
auto plan = Patch::at(other); // locate 的原始错误同样保留到 apply()
```

这些入口不会自动忽略查找错误，也不会重新扫描。需要打印查找上下文时，可以用带错误参数的恢复 / 观察回调：

```cpp
auto site = scan(signature).in(module).unique().or_else([](const Error& error) {
    report(error.format()); // 返回 void：观察错误，失败状态继续保留
});
```

原有无参数 `or_else([] { ... })` 保持可用。如果回调同时支持两种调用形式，优先传递 `const Error&`。只有失败时才调用；回调可返回另一个结果实现明确的回退策略。

## 类型化读写

数值可以直接使用 `.expect<T>(value)` / `.write<T>(value)`，无需手工拆成小端字节：

```cpp
auto blending = ipatch::Patch::search("48 81 7E ? 10 27 00 00 0F 82")
    .unique()
    .offset(4) // imm32 的起点，不是 offset(6)
    .expect<std::uint32_t>(0x2710) // 十进制 10000 同样可用
    .write<std::uint32_t>(0x00102710)
    .apply();
```

这里 `0x00102710` 等价于原来的 `offset(6).write({0x10})`；如果想写其他数值，直接修改参数即可。`expect` 不推进游标，`write` 推进 `sizeof(T)` 字节；类型宽度必须与目标字段一致。x86-64 上按小端对象表示比较、写入。

支持整数和浮点数，也支持推导：`.expect(1.0f).write(2.5f)` 操作四字节 float。注意 `.write(0x10)` 使用整数常量的类型（这里是四字节 int），`.write({0x10})` 仍只写一个字节。建议整数显式指定 `std::uint8_t/uint16_t/uint32_t/uint64_t` 或对应有符号类型。显式模板参数的实参转换遵循 C++ 规则，调用者需确保数值可由该类型表示。

## 替换跳转，保留目标和后续地址

```cpp
auto branch = ipatch::Patch::search("0F 85 ?? ?? ?? ?? 48 8B")
    .unique().replace_branch(ipatch::x64::Branch::jmp).apply();
// jne -> jmp，原跳转目标不变
// 改条件也可以：replace_branch(ipatch::x64::Branch::je)
```

`replace_branch` 从当前游标读取一条无前缀的直接 `Jcc/JMP`，支持 short / near 编码和全部 16 种条件（含 `jz/jnz` 等别名）。它保持原指令起始地址、占用范围和跳转目标，游标前进原指令长度。两字节分支原地改操作码；六字节 Jcc 转 JMP 时重算 rel32，生成五字节 JMP 加一个 NOP。补丁对象销毁或 `restore()` 时恢复原始字节。

原始字节在 `apply()` 时自动复核，显式 `.expect(...)` 也会保留；`.verify(false)` 会关闭这两种检查。五字节 near JMP 改六字节 Jcc 返回 `insufficient_space`，调整后的 rel32 溢出返回 `out_of_range`；带前缀、间接跳转、CALL、LOOP 和非跳转指令返回 `unsupported_instruction`。因此不会为扩展指令覆盖后续代码。

## 读取数值与通用对象读写

```cpp
auto speed = scan(signature).in(module).unique().rel32(3, 7);
auto old = speed.read<float>(); // Result<float>，检查可读性后复制字节
if (!old) {
    report(old.error().format());
    return;
}
auto patch = Patch::at(speed).expect_value(*old).write_value(2.5f).apply();
```

`read<T>()` 支持非 const、非 volatile、非数组的 trivially-copyable 类型。它返回值副本，允许未对齐地址；不会把目标内存强转为引用。页面可读性检查不替代生命周期同步，读取期间仍需保证模块 / 缓冲区有效。

`write_value(value)` 和 `expect_value(value)` 复用原有事务与原字节验证逻辑。写入会推进游标 `sizeof(T)` 字节，期望值检查发生在 `apply()` 阶段。它们处理对象的字节表示：

- `2.5f` 是 float，`2.5` 是 double；建议整数使用 `std::uint32_t{42}` 等显式宽度。
- 指针值写入的是地址本身，不会复制指针指向的内容。
- 结构体可能含 padding，字节比较不会忽略 padding；稳定协议或签名优先使用明确的字段或字节数组。
- 不支持 `std::string` 等非 trivial-copy 对象；字符串内容继续通过文本 / 字节接口处理。

## 直接访问指针和引用

`read<T>()` 返回独立副本；`ptr<T>()` 返回 `Result<T*>`，`ref<T>()` 返回 `Result<std::reference_wrapper<T>>`，后两者直接访问目标对象：

```cpp
auto site = scan(signature).in(module).unique().rel32(3, 7);
auto pointer = site.ptr<float>();
if (!pointer) { report(pointer.error().format()); return; }
float* speed = *pointer;
*speed = 2.5f; // 立即修改目标

auto reference = site.ref<float>();
if (!reference) { report(reference.error().format()); return; }
float& speedRef = reference->get();
speedRef = 3.5f;

auto readOnly = site.ptr<const float>(); // 允许只读页面
```

`Patcher` 上也可直接调用，使用包含 `offset/skip/rel32` 的当前游标：

```cpp
auto pointer = Patch::search(signature).in(module).unique().offset(4).ptr<const std::uint32_t>();
// 同样支持 .ref<T>() 和 .read<T>()；不推进游标，不执行计划中的写入。
```

借用访问检查 `alignof(T)` 和整个 `sizeof(T)` 范围。未对齐返回 `invalid_argument`，应使用允许未对齐的 `read<T>()`；不可读返回 `access_denied`。非 const T 还要求所有页面可写，不会自动更改页面保护。查找失败保留原错误。

目标必须存在匹配类型的有效对象，并由调用者保持其生命周期和访问同步。检查仅反映调用时的页面状态，不延长对象或模块的寿命。指令中的立即数字节不应视为活的 C++ 数值对象，继续使用 `read<T>()` / `write<T>()`。通过指针或引用修改立即生效，不经过 `expect/apply`，不会自动还原，也不会自动刷新指令缓存；需要可还原补丁时仍用 `write<T>().apply()`。

`ptr<T>()` 是目标地址处的 T 指针；如果目标存储的就是一个指针，`read<T*>()` 读取其中保存的指针值，`ptr<T*>()` 则取得该指针槽的地址（T**）。

## 基址和游标明确区分

```cpp
auto plan = Patch::search(signature);
plan.in(module).unique().offset(5);
auto base = plan.find();     // 保留旧语义：搜索基址，不含 offset
auto cursor = plan.cursor(); // 真正准备写入的位置
plan.write_value(std::uint32_t{42});
auto next = plan.cursor();   // 再前进四字节，但还没有提交写入
```

`.cursor()` 和 `.find()` 都会解析搜索条件，所以 `.in()`、`.unique()` 等配置仍应放在它们之前。`rel32()` 将目标设为新的基址，之后 `find()` 返回该基址。使用 `.cursor()` 避免把原始签名地址误认为最终写入位置。

## Hook 自动利用已知签名

```cpp
int target(int value);
int replacement(int value);

auto direct = Hook::create(&target, &replacement);
// 直接转发匹配的函数指针；无需 reinterpret_cast<void*>。

auto captured = Hook::create(&target, [bias = 100](int value) {
    return value + bias;
});
```

以上是互斥的安装示例，不要同时向同一个入口安装两个 Hook。目标函数指针提供签名，普通指针 / 可直接转换的无捕获 lambda 使用原生路径；捕获式回调或需要返回值转换的回调使用适配器。参数与返回值需要满足目标签名的调用规则。目标若标记 `noexcept`，回调及返回值转换也必须不抛异常，否则编译期拒绝。

扫描所得地址没有 C++ 类型，需要明确指定签名，但不用取出裸地址：

```cpp
auto address = scan(signature).in(module).unique().rel32(1, 5);
auto hook = Hook::create_typed<int(int)>(address, [bias](int value) {
    return value + bias;
});
```

`locate(...)` 的 `Result<std::byte*>` 同样可传入。查找失败时保留原始错误，并且不会移动回调对象或创建 Hook 资源。`create_typed` 也支持直接传函数名，空函数指针会被拒绝。安装过程中回调持有对象由 RAII 管理，成功后交给 Hook 持有。

## 结果生命周期

从临时对象调用 `.raw()` 现在返回一个拥有自身内容的 `Result<std::byte*>`，例如 `const auto& value = scan(...).first().raw()` 不再引用已经销毁的 `MatchResult` 内部成员。

从左值 `.raw()` 仍返回 const 引用，此引用不能超出原结果对象生命周期。构造输入为“成功但地址为 nullptr”的 expected 时，会规范化为 `not_found`，保证成功的 `MatchResult` 总是有非空地址。

## 审查后的后续方案

本轮落实了以上能够复用现有执行层的改进。下面的候选方案按使用收益排序，尚未实现：

| 优先级 | 方案 | 解决的问题与设计边界 |
| --- | --- | --- |
| 高 | 命名 runtime 槽位描述 | 把类型、基址寄存器、偏移放进统一描述，例如 `health`；回调只通过描述读写。描述须按目标版本维护，不自动猜测源码局部变量。 |
| 高 | Patcher 阶段约束和只读计划预览 | 解析后修改搜索选项应明确报错；提供写入范围、原值和新值预览，使偏移错误更容易在 apply 前发现。预览不承诺执行时内存保持不变。 |
| 中 | `TypedHook<Signature>` 持有类型 | 安装后 `original()` 保留目标函数类型，避免再次写 `original<int(*)(int)>()`。需要确定移动与原始函数句柄的生命周期规则。 |
| 中 | 为失败附加操作名称和地址 | 记录是扫描、相对解析、期望值验证还是恢复失败；保留现有 ErrorCode，避免仅为日志引入复杂异常体系。 |

