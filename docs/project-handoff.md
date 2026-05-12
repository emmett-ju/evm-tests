# EVM RPC Tests 项目接手说明

## 读者与用途
本文面向下一位接手这个项目的内部工程师。

读完后，接手人应当能够：
- 理解这个项目为什么存在。
- 理解当前 harness 的核心工作机制。
- 识别哪些 upstream family 已经迁移，哪些还没有。
- 继续扩展新的 execution-specs family，而不需要先重新梳理历史上下文。
- 判断当前 benchmark family 覆盖是否值得继续扩展；最新覆盖状态见 `docs/benchmark-coverage-status.md`。

## 项目背景
这个项目的目标，不是把 `execution-specs` 原样搬过来跑一遍，而是把其中能够在专用 RPC 链上表达的执行层用例，迁移成一套可重复运行的本地 harness。

这里的目标链有几个硬约束：
- 只能通过 RPC 访问。
- 链是专用环境，但不能随意重置。
- 不能修改创世状态。
- 真实 RPC 默认不支持 unlocked account。
- 第一阶段接受“最终链上状态和 receipt 断言”为真值，不追求和 upstream `t8n` 或 gas benchmark 完全等价。

这决定了项目必须放弃 upstream 的主路径，也就是 `fill -> fixture -> t8n`，改成另一条路线：
- 从 upstream 测试源码中自动扫描可承接的 case。
- 生成本地模板和 manifest。
- 通过本地 RPC harness 部署最小合约、发交易、读取链上状态。
- 用最终状态、receipt、code、storage 等结果做断言。

## 设计原则
- upstream `execution-specs` 作为只读基线，不做本地修改。
- 优先自动扫描、自动分类、自动生成；尽量避免手工维护大量 case JSON。
- 只承接“最终链上可观测”的语义子集。
- 不能安全表达的 case 不伪装支持，必须进入 inventory 并给出过滤原因。
- 真实链和 mock 链走同一套 manifest 语义，减少双轨维护。

## 当前实现机制

### 1. 上游接入方式
upstream 通过 git submodule 接入，只读使用。

本地不会修改 upstream 仓库；所有本地适配都发生在 scanner、generator、selector、executor 和 suite 产物上。

### 2. 三层产物结构
当前项目可以理解成三层：

第一层：upstream 源
- 只读基线。
- 提供 benchmark family 的原始测试定义。

第二层：adapter
- 负责 profile、selector、bootstrap、executor、oracle、CLI。
- 也负责各 family 的自动扫描器和 manifest 生成器。

第三层：suites
- 保存模板、inventory 和最终 manifest。
- 模板表示“已知可以映射的 case”。
- inventory 表示“全量扫描结果及过滤原因”。
- manifest 表示“最终可运行的本地测试集”。

### 3. 执行链路
当前标准链路如下：

1. 扫描 upstream family 源码。
2. 自动分类为 admitted 或 blocked。
3. 对 admitted case 生成本地模板。
4. 用模板生成 manifest。
5. `run` 命令读取 manifest，经 selector 过滤后执行。
6. bootstrapper 为每个 case 分配幂等 namespace。
7. executor 部署合约、发送交易、轮询 receipt、读取 storage/code/balance。
8. oracle 对 expected 和 observed 做最终比较。
9. report 输出机器可读结果。

### 4. backend 模型
当前有两个 backend：

`mock`
- 用于本地自测和回归测试。
- 通过模拟固定 bytecode 语义，验证 scanner、manifest、executor、oracle 的联动。

`jsonrpc`
- 用于真实链执行。
- 通过 RPC 发送交易、等待 receipt、读取 storage/code/balance。
- 管理员账户默认从 `.env` 中读取私钥并本地签名发送 EIP-1559 交易。

### 5. 占位符机制
为了支持运行时动态值，当前 harness 已经引入 expected 占位符解析能力。

已经支持的典型占位符包括：
- `$last_contract_word`
- `$admin_account_word`

这类占位符会在执行结束后，结合运行时上下文解析成最终 32-byte word，再进入断言阶段。

这个能力是后续继续迁移调用类、交易上下文类、地址类 family 的关键基础设施。

## 当前已支持或已建账的 family

### 已形成 runnable 闭环的 family

#### storage
已完成自动扫描、模板生成、manifest 生成和运行验证。

当前已映射 17 个 case，覆盖：
- `SLOAD`
- `SSTORE`
- success
- revert
- out_of_gas
- warm/cold 的可观测子集

#### memory
已完成自动扫描、模板生成、manifest 生成和运行验证。

当前已映射 5 个 case，覆盖：
- `MLOAD`
- `MSTORE`
- `MSTORE8`
- `MSIZE`

#### call-context
已完成自动扫描、模板生成、manifest 生成和运行验证。

当前已映射 20 个 case，覆盖：
- `ADDRESS`
- `CALLER`
- `CALLVALUE`
- `CALLDATASIZE`
- `CALLDATALOAD`

这部分迁移已经依赖运行时占位符能力，并已收口当前可观测的 calldata size / data-shape 矩阵。

#### tx-context
已完成第一阶段自动扫描器与最小 runnable 子集。

当前已映射 2 个 case：
- `ORIGIN`
- `GASPRICE`

当前进入 inventory 但尚未承接的包括：
- `BLOBHASH`

`BLOBHASH` 仍被延后，因为它需要额外的 blob 交易构造与观测能力。

#### account-query
已完成第一批最小 runnable 子集。

当前已映射 5 个 case：
- `SELFBALANCE`
- `CODESIZE`
- `BALANCE`（present / absent account 变体）

这部分已经具备：
- scanner
- checked-in inventory / template
- manifest
- selector
- mock backend 执行
- checked-in artifact parity 回归

当前仍 blocked 的主要是：
- `CODECOPY`
- `EXTCODECOPY`
- 相关外部代码字节观测子集

### 已建立 inventory 但尚未进入 runnable 映射的 family
- `arithmetic`
- `bitwise`
- `comparison`
- `control-flow`
- `stack`

这些 family 已有 family-local scanner、checked-in inventory 和 summary 覆盖，但目前仍是 blocked-only inventory。

## 当前尚不支持的能力边界
以下能力目前仍不在 v1 承接范围内：
- 强依赖创世预置状态的 case。
- 强依赖 block 组装和 block-level 环境控制的 case。
- 要求 trace 严格等价的 case。
- 要求精确 gas benchmark 对齐的 case。
- 需要完整 blob/base fee/withdrawal 环境控制的 case。
- 需要复杂多交易序列、多合约交互编排、且最终状态无法用当前最小模型表达的 case。

## 当前常用工作流

### 1. 扫描并生成某个 family
典型命令模式如下：

```bash
python -m adapter.cli scan-upstream-<family> --template-output <template> --inventory-output <inventory>
python -m adapter.cli generate-<family>-manifest --template <template> --output <manifest>
```

### 2. 运行某个 manifest
```bash
python -m adapter.cli run --profile profiles/mock.toml --manifest <manifest> --state-dir .state
```

真实链运行时：
- 使用 `profiles/juchain.toml`
- 私钥从 `.env` 加载
- 由本地签名发送交易

### 3. 回归验证
当前最重要的回归入口是：

```bash
python3 -m unittest discover -s tests -v
```

这套测试覆盖了：
- profile 解析
- selector 过滤
- scanner 输出
- manifest 生成
- mock backend 执行
- oracle 占位符解析
- CLI 运行链路

## 当前进展总结
项目已经从“手写少量 case”推进到“按 family 自动扫描、生成 inventory，并逐步把 supportable 子集转成 runnable manifest”。

截至目前：
- 已有 inventory 的 family 共 10 个：
  - `storage`
  - `memory`
  - `call-context`
  - `tx-context`
  - `account-query`
  - `arithmetic`
  - `bitwise`
  - `comparison`
  - `control-flow`
  - `stack`
- 其中具备 runnable admitted 子集的有 5 个：
  - `storage`
  - `memory`
  - `call-context`
  - `tx-context`
  - `account-query`

里程碑状态：
- `M001` 已完成：补齐 `arithmetic / bitwise / comparison / control-flow / stack` 的 family-local inventory 与 summary 闭环。
- `M002` 已完成：补齐 `account-query` 第一批最小 runnable 子集（`SELFBALANCE / CODESIZE / BALANCE`），并加上 checked-in artifact parity 回归。

项目当前已经不再处于“只证明路线可行”的阶段，而是进入了：
- 补完剩余 inventory 账本
- 收口半完成 family
- 批量把 blocked-only family 转成 runnable admitted 子集

## 建议的后续推进顺序

### 第一优先级：补完剩余 inventory
优先补上计划里还没有 inventory 的 family：
- `keccak`
- `log`
- `block-context`
- `system`

原因：
- 先把总盘子补齐，后续才能真实判断 coverage 封账进度。
- 现在已经有稳定的 summary 路径和 checked-in inventory 约束，继续补账本成本最低。

### 第二优先级：收口已半完成 family
重点处理：
- `memory`
- `call-context`
- `tx-context`

原因：
- 这些 family 的大量 blocked 仍是“实现缺口”，而不是能力边界。
- 补齐它们的收益高于立刻开更复杂的 system/log 路径。

### 第三优先级：抽通用原语
建议在继续扩 family 之前，逐步补强：
- 更通用的 probe contract 生成方式
- 更丰富的 runtime placeholder
- receipt logs / topic / data hash 等观测面

原因：
- 这会直接决定后续 `block-context / log / system` 的边际成本。

### 第四优先级：推进纯语义 family runnable 化
在 inventory 已有的 family 中，优先把这些 blocked-only family 逐步转成 admitted runnable 子集：
- `arithmetic`
- `bitwise`
- `comparison`
- `control-flow`
- `stack`
- `keccak`（前提是先补 inventory）

### 第五优先级：继续 account-query 第二批与日志/区块上下文
`account-query` 第一批已经完成，后续重点是：
- `EXTCODESIZE`
- `EXTCODEHASH`
- `CODECOPY`
- `EXTCODECOPY`

并行推进：
- `block-context`
- `log`

### 最后：system family
`system` 仍然是风险最高的一组，建议最后处理：
- `CALL`
- `STATICCALL`
- `DELEGATECALL`
- `CALLCODE`
- `RETURN / REVERT`
- `CREATE / CREATE2`
- `SELFDESTRUCT`

## 下一位接手人需要注意的事项
- 不要把 upstream case 手工一条条抄进 manifest；优先补 scanner。
- 不要为了“支持更多 case”而绕开 inventory；blocked 原因本身就是重要产物。
- 不要把 mock backend 做成与真实 EVM 完整等价；它的职责是支撑 harness 回归，不是实现一个客户端。
- 新 family 一定要同时补四类内容：
  - scanner
  - manifest 生成
  - mock backend 语义
  - unittest 回归
- 新的运行时动态值，优先通过执行上下文和 placeholder 体系接入，不要在模板里写死。

## 推荐的接手动作
如果下一位接手人要继续推进，推荐第一步直接做下面这件事：

1. 选定一个新 family。
2. 明确其中“最终状态可观测”的最小子集。
3. 先写 scanner 和 inventory。
4. 再补最小 manifest 生成。
5. 再补 mock backend 语义和回归测试。
6. 最后再扩 coverage。

这条路径已经在 storage、memory、call-context、tx-context 上验证过，风险最低。
