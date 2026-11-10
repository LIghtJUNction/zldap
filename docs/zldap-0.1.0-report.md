# zldap 0.1.0 工程交付报告

日期：2026-11-10（Asia/Taipei）。实现与最终性能测量源码：[68f0bfeb762e3f6e84bea323771772d6b4808e98](https://github.com/LIghtJUNction/zldap/commit/68f0bfeb762e3f6e84bea323771772d6b4808e98)。

## 交付结果

`zldap` 已实现为独立 LDAP/BER 协议 crate，代码已分阶段提交到 [LIghtJUNction/zldap](https://github.com/LIghtJUNction/zldap)。正式 crate 始终 `#![no_std]`，只使用 `core`，无普通、开发、构建、可选或目标平台第三方依赖；无 `alloc`、`build.rs`、FFI，使用 `#![forbid(unsafe_code)]`。MSRV 为 Rust 1.74，已实际编译和测试。

最终固定版本对照的 11 个完整 LDAP 解码场景全部超过 2×：范围为 2.45×–17.66×。该结果描述本次机器和语料下的协议编解码路径，完整字段和消息边界在测量前经过差分验证。未测量 Kanidm 身份服务器、网络、TLS、数据库或认证决策。

当前 Cargo 版本为 **0.1.0**。发布自动化已实现，**本次尚未发布 crates.io、创建版本 Tag 或 GitHub Release**。当前执行环境没有发布凭据，已连接 GitHub 接口没有手动触发 Actions 的能力，浏览器 GitHub 会话未登录。仓库中是否已配置 `CARGO_REGISTRY_TOKEN` Secret 未经确认；执行环境中没有该变量，不能据此判断仓库 Secret 的状态。发布前已查询 crates.io：`zldap 0.1.0` 当时未被占用，真正发布时工作流会再次检查。

## 协议与 API

| 层 | 已实现能力 |
| --- | --- |
| BER | Tag（包括 high-tag-number）、确定长度、借用 TLV、INTEGER、ENUMERATED、BOOLEAN、原始 OCTET STRING、SEQUENCE、SET、反向 Writer |
| LDAP | LDAPMessage、Message ID、Simple/SASL BindRequest、BindResponse、SearchRequest、SearchResultEntry、SearchResultDone、UnbindRequest |
| Filter | AND、OR、NOT、Equality、Substrings、GreaterOrEqual、LessOrEqual、Present、ApproxMatch、ExtensibleMatch |
| 可选协议字段 | Controls、criticality、opaque controlValue、referrals、serverSaslCreds、缺省与空值区分 |
| 失败处理 | 结构化 ErrorKind 与偏移、UnsupportedOperation、容量不足、截断、溢出、资源限额 |

`Message::parse` 完整验证一条消息；`parse_prefix` 返回首条消息及消耗长度，适合调用方维护的网络缓冲区和消息批次。解析返回前已检查所有属性、Filter 子节点和 Controls；调用方无需遍历结果来触发验证。`MessageInput::encoded_len` 计算准确容量，`encode` 写入调用方切片；容量或协议字段出错时输出保持不变。`Message::copy_encoded` 保留包括未知扩展在内的原始编码。

协议数据与认证决策分离。Simple 密码、SASL 凭据、属性值和断言值保留二进制内容；LDAP 元数据检查 UTF-8。空 SASL mechanism 按 RFC 4511 保留为中止协商的协议信号，由应用决定并发送响应。Bind 调试输出隐藏凭据。DN 与 referral URI 不在此实现完整目录语法和 URI 语法；调用方负责相应语义。

## 默认资源限额与安全验证

| 资源 | 默认值 | 行为 |
| --- | ---: | --- |
| 整条 BER 编码长度 | 1,048,576 字节 | 声明长度超限时可在消息体到达前拒绝 |
| TLV 嵌套深度 | 32 | 根节点计作第一层；使用调用方 Frame 切片 |
| TLV 总数量 | 65,536 | 包含容器、空节点、未知扩展和所有后代 |
| 每个 primitive value 长度 | 1,048,576 字节 | 包括二进制属性、凭据和其他原始值 |
| 工作区容量 | 调用方指定 | 不足返回 WorkspaceTooSmall |

所有限额均可通过 `ParseLimits` 设置。解析器不递归，也不按输入长度创建栈数组。小消息快速路径对完整字段、容器结束位置、整数符号与范围、UTF-8、字段数、深度、primitive 长度和工作区容量逐项检查；其余编码使用通用路径。合法的非最短 BER length 被接受；INTEGER 要求最短有符号表示，LDAP 布尔 true 要求 `FF`，包括未知扩展内部。原始 OCTET STRING 内嵌内容保持 opaque。

已通过 72 项核心测试和 1 项 README 文档测试；独立对照工程有 10 项差分测试；发布脚本有 10 项测试。测试包括 BER 向量、独立编码字节核对、round-trip、逐字节截断、容量事务性、资源耗尽、深/宽 Filter、非法 UTF-8、整数边界、特殊空值、错误类别，以及 90,000 条确定性随机输入。快速路径另与强制通用路径比较了 14,040 对有效编码，覆盖 0–129 字节值长度和正整数编码边界。

[实现提交的 GitHub CI](https://github.com/LIghtJUNction/zldap/actions/runs/42755915828) 已成功完成 Linux/macOS/Windows × MSRV/stable、fmt、clippy、test、doc、WASM/嵌入式/aarch64 编译、Miri、差分和打包预检查。实际工具链与最终本地验证记录见 [VERIFICATION.md](VERIFICATION.md)。Miri 与随机测试提供执行证据；项目没有宣称穷举所有输入或完成形式化证明。

## 对照方法

对照固定为 Kanidm 的 `ldap3_proto = 0.9.0` 和 `ldap3_lber = 0.9.0`，源码标识 `f1ec51111756a6ea941a0685827283bb55bb94ac`，传递依赖由独立 `comparison/Cargo.lock` 锁定。该工程和分配计数器不进入正式 crate 的依赖图或发布包。

最终测量使用 Intel Xeon Platinum 8573C、Rust 1.99.1、固定允许 CPU 0、9 个样本，每个样本最多 100,000 条消息或 64 MiB 输入，报告中位数。计时二进制使用系统分配器；堆分配测量使用独立构建，避免计数器污染延迟。运行前后源文件哈希一致，测量源码没有未提交补丁。样本间波动范围保留在 CSV 的 min/max 列；这些数值不是置信区间。

### 完整 LDAP 解码

吞吐量与每字节成本均为 zldap 实测值。批次场景按单条消息归一化。

| 场景 | zldap ns/条 | 对照 ns/条 | 比值 | zldap 百万条/秒 | zldap ns/字节 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 小型 Bind | 53.8 | 354.0 | 6.58× | 18.580 | 0.961109 |
| SASL Bind | 59.6 | 420.1 | 7.04× | 16.764 | 1.656948 |
| BindResponse | 53.3 | 393.1 | 7.37× | 18.753 | 2.806561 |
| 简单 Search | 263.5 | 731.5 | 2.78× | 3.795 | 3.992238 |
| 复杂 Search Filter | 917.8 | 2,696.0 | 2.94× | 1.090 | 4.060998 |
| 128 个属性的 Entry | 9,681.7 | 30,742.3 | 3.18× | 0.103 | 1.469372 |
| 128 KiB 属性值 | 231.0 | 4,079.9 | 17.66× | 4.329 | 0.001761 |
| SearchResultDone | 51.5 | 363.7 | 7.07× | 19.427 | 2.339723 |
| Unbind | 50.7 | 202.9 | 4.01× | 19.740 | 7.237101 |
| 256 条 Bind 批次（按条） | 49.3 | 337.1 | 6.84× | 20.293 | 0.872103 |
| 128 条 Entry 批次（按条） | 752.0 | 1,845.0 | 2.45× | 1.330 | 1.075874 |

### 堆分配与内存

| 场景 | zldap 分配/条 | 对照分配/条 | zldap 新增堆峰值 B | 对照堆峰值 B |
| --- | ---: | ---: | ---: | ---: |
| 小型 Bind | 0 | 6 | 0 | 428 |
| SASL Bind | 0 | 7 | 0 | 596 |
| BindResponse | 0 | 5 | 0 | 391 |
| 简单 Search | 0 | 14 | 0 | 808 |
| 复杂 Search Filter | 0 | 55 | 0 | 3,775 |
| 128 个属性的 Entry | 0 | 522 | 0 | 61,229 |
| 128 KiB 属性值 | 0 | 9 | 0 | 132,069 |
| SearchResultDone | 0 | 5 | 0 | 394 |
| Unbind | 0 | 2 | 0 | 193 |
| 256 条 Bind 批次（按条） | 0 | 6 | 0 | 429 |
| 128 条 Entry 批次（按条） | 0 | 38 | 0 | 4,460 |

zldap 在全部实测阶段为 0 次堆分配、0 字节新增堆峰值。上述数字排除预先存在的输入、输出和工作区；在测量的 64 位架构上，32 个 Frame 为 512 字节，Message 视图为 192 字节。单独用 `wait4` 测得整个基准进程 RSS 峰值为 12,058,624 字节（11.5 MiB），包含两套库、全部语料及调用方缓冲区，不包含编译器进程。这项 RSS 不归属于某一个解析器。

### 性能结论的适用范围

128 KiB 属性值的完整解码提升为 17.66×，主要来自借用该值、避免分配和复制。额外读取并哈希每个字段与属性字节时，zldap 为 209,567.8 ns/条，对照为 209,006.0 ns/条，比值约 0.997×，基本持平。对 opaque 二进制字段的协议验证需要验证长度与结构；全字节读取的应用工作量另列，不混入解码优势结论。

单独 BER 阶段测得 3.10×–43.08×，比较的是完整 BER 验证和借用根视图与对照的 owned BER 树。重复编码阶段测得 3.77×–55.68×：对照原生 API 消耗输入，测量计入必要克隆；zldap 借用输入并复用预验证 Filter。这些编码数字按原生 API 契约解释，不宣称相同底层复制操作有该倍数差异。

畸形输入、超长输入和不支持操作的分类与耗时保存在 errors.csv 和 rejection_policy 行，未计入速度领先结论。差分测试明确记录参考库对部分畸形输入的宽松接受、SASL 缺省与空值归一化、特定 referral 字段丢失以及字符串/二进制表示差异。

完整原始结果：[最终报告](../comparison/results/20261110-final/REPORT.md)、[results.csv](../comparison/results/20261110-final/results.csv)、[metadata.json](../comparison/results/20261110-final/metadata.json)、[错误分类](../comparison/results/20261110-final/errors.csv)。初始实现基线保留在 [baseline](../comparison/results/20261110-baseline/REPORT.md)。

## 复现

```sh
cargo test --locked
cargo +1.74.0 test --locked
cargo clippy --locked --all-targets -- -D warnings
MIRIFLAGS=-Zmiri-strict-provenance cargo +nightly miri test --locked --lib --tests
python3 scripts/check_package.py
cargo test --manifest-path comparison/Cargo.toml --locked
python3 comparison/run.py --output comparison/results/local --iterations 100000 --samples 9
cargo run --example search
```

## 发布工作流

[Release 工作流](https://github.com/LIghtJUNction/zldap/actions/workflows/release.yml) 的 `workflow_dispatch` 支持 `current`、`patch`、`minor`、`major`。首次发布当前 0.1.0 选择 `current`。Bump 同步根 Cargo.toml、根 Cargo.lock 和 comparison 锁文件中的本地 zldap 版本，保留对照第三方锁定版本。

工作流先校验默认分支和确切提交，再执行完整复用 CI、package、版本占用检查，使用仅在发布步骤注入的 `CARGO_REGISTRY_TOKEN` Secret 执行 cargo publish。发布的 crate checksum 校验完成后，在同一次运行中创建 Tag 与 GitHub Release；不依赖 GITHUB_TOKEN 创建 Tag 后再触发另一个工作流。PR 不接触发布密钥，日志不输出凭据。`resume=true` 仅允许与已经上传归档完全相同的版本继续补齐发布结果。

## 依据与自检

- 协议依据：[RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)、[RFC 4512](https://www.rfc-editor.org/rfc/rfc4512)。支持的字段、默认值、SASL 空 mechanism 和编码规则均在实现与测试中对应。
- 性能主张：由固定源码、独立差分测试、CSV 中位数和分离的分配测量支持；不外推到完整身份服务器。
- 实验完整性：同时报告小消息、复杂结构、大值、批次、失败输入、逐字节读取和内存口径。
- 方法边界：借用视图与 owned 结果的差异是本次 API 层测量的一部分；数据读取或业务处理可能成为新的主要成本。
- 交付状态：源码、测试、CI、版本 bump 和发布链路均已实现；实际 registry/Tag/Release 发布仍待具备认证权限的执行入口。
