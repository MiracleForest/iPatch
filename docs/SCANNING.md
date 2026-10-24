# 扫描与地址转换

## 入口选择

| 输入与目的 | 接口 |
| --- | --- |
| 十六进制特征码 | `scan("48 8B ??")` |
| ASCII / UTF-8 原始字节 | `scan_string("text")` |
| UTF-16LE | `scan_string(u"文本")` |
| 需要复用、命名或复合模式 | `Pattern::from_string(...)` / `Pattern::parse(...)` |
| 唯一签名加偏移 | `locate(range_or_module, signature, offset)` |
| 唯一文本加偏移 | `locate_string(range_or_module, text, offset, null_terminated)` |
| 从文本开始构建补丁 | `Patch::search_string(text, null_terminated)` |

字符串参数使用 `string_view` / `u16string_view`，但构建查询时会复制为模式字节，不会保存调用者的视图。空字符串总是无效，即使开启终止符匹配也不会变成搜索单个 NUL。

`null_terminated` 默认为 `false`，因此 `"config"` 可以匹配 `"configuration"` 的开头。开启时附加一个 NUL code unit；如果输入视图自身包含 NUL，会照常保留并再附加一个。UTF-16 按 little-endian code unit 生成字节，支持代理对；不验证 Unicode 合法性。

## 范围和匹配策略

普通 `scan` 默认选择主模块的可执行节。`scan_string` 默认选择可读节，包括 `.rdata` 和 `.data`；可用 `.executable_only(true)` 改为代码节。`scan(Pattern::from_string(...).value())` 仍使用普通扫描的默认代码范围，需要显式设置 `.executable_only(false)` 才会包含数据节。

`.in(range)` 可以重复调用；`.in(module)` 可选择多个模块；`.in_process()` 枚举当前进程内存。显式范围不受 `executable_only()` 过滤，但必须可读。选中的范围含有不可读页面时返回 `access_denied`，不会读取该页面或悄悄扩大范围。模块没有符合条件的节时，`all()` 返回空向量，`first()` / `unique()` 返回 `not_found`。

相邻或重叠范围会合并，避免重复扫描；对齐相对于合并后范围的起点。`Pattern::find_all()` 保留重叠匹配，对齐始终使用原始传入范围的起点。

`first()` 按地址选择最早匹配；同一地址有多个备选模式时按模式索引选择。`require_first()` 保留真实的模式索引和名称，不会脱离扫描范围重新匹配。

`unique()` 与 `require_unique()` 要求匹配记录只有一条。不同备选模式在同一地址匹配也会造成 `ambiguous`。`limit()` 不参与唯一性判断，内部找到两条记录即可停止。

## 地址链

```cpp
auto target = ipatch::scan("E8 ?? ?? ?? ?? 84 C0")
                  .in(module)
                  .unique()
                  .rel32(1, 5)
                  .offset(-8);
if (!target) {
    report(target.error().format());
    return;
}
auto target_rva = target.rva(module);
```

| 操作 | 语义 |
| --- | --- |
| `offset(n)` | 当前地址加有符号字节偏移，不读内存 |
| `rel32(d, n)` | 在当前地址 `+d` 读取 `int32_t`；目标为当前地址 `+n+disp32` |
| `rva(module)` | 转为模块内偏移；地址必须位于 `[base, base+size)` |
| `read<T>()` | 检查可读性后复制类型化值，返回 `Result<T>` |
| `raw()` | 左值取底层 expected 的 const 引用；临时结果返回拥有内容的 expected |
| `value()` / `address()` | 成功返回地址，失败返回 `nullptr` |

`rel32()` 默认 `(0, 4)`，用于当前地址已指向位移字段的场景。常见 `E8/E9` 用 `(1, 5)`，`0F 8x` 条件跳转用 `(2, 6)`，七字节 `48 8B/8D ...` 用 `(3, 7)`。有前缀或尾部立即数的指令应根据真实布局指定参数，不能一律套用这些数字。

错误会短路传播。地址偏移和补丁游标偏移共用 `src/address.hpp`，检查整数上溢、下溢及零地址结果。这里没有将结果限制在扫描范围内，因为合法的相对分支可能指向其他区域。`rel32` 只读取位移，不检查目标是否可执行，也不会解引用目标处存储的指针。

## 补丁链的求值顺序

```cpp
auto patch = ipatch::Patch::search("E8 ?? ?? ?? ?? 84 C0")
                 .in(module).unique()
                 .rel32(1, 5)
                 .offset(2)
                 .expect({0x90})
                 .write({0xCC})
                 .apply();
```

在 `.rel32()`、`.end()` 或首次写入前指定范围、匹配策略和签名条件。`.offset()` 和 `.skip()` 在解析前累积，在解析后移动游标。`.rel32()` 解析当前游标处的相对目标，并将新目标设为游标和基址，后续写入以此继续。

多个写入仍归属于同一次事务。定位或算术失败后，`apply()` 返回错误，已有计划不会部分写入。修改数据字符串时应自行确认目标缓冲区容量，写入接口不会自动扩展字符串存储空间。

## 生命周期

这些接口针对当前进程。扫描范围必须在整个扫描期间有效，不能并发卸载模块、释放缓冲区或改变页面保护。`VirtualQuery` 检查只能发现当时不可读的页面，不能代替生命周期同步。

底层 `Pattern` 是纯字节匹配器，不查询 Windows 页保护。直接调用 `matches(address)` 时需要提供 `max_size()` 可读字节；不确定可用长度时使用带 `Range` 的查找接口。复合模式使用有界回溯，病态的超复杂签名可能耗尽预算；优先用稳定且区分度高的锚点缩小条件。
