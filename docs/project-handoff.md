# EVM RPC Tests 项目接手说明

## 读者与用途
本文面向下一位接手这个项目的内部工程师。

读完后，接手人应当能够：
- 理解这个项目为什么存在。
- 理解当前 harness 的核心工作机制。
- 识别哪些 upstream family 已经迁移，哪些还没有。
- 继续扩展新的 execution-specs family，而不需要先重新梳理历史上下文。

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

## 当前已支持的 family

### storage
已完成自动扫描、模板生成、manifest 生成和运行验证。

当前已映射 17 个 case，覆盖：
- `SLOAD`
- `SSTORE`
- success
- revert
- out_of_gas
- warm/cold 的可观测子集

### memory
已完成自动扫描、模板生成、manifest 生成和运行验证。

当前已映射 5 个 case，覆盖：
- `MLOAD`
- `MSTORE`
- `MSTORE8`
- `MSIZE`

### call-context
已完成自动扫描、模板生成、manifest 生成和运行验证。

当前已映射 9 个 case，覆盖：
- `ADDRESS`
- `CALLER`
- `CALLVALUE`
- `CALLDATASIZE`
- `CALLDATALOAD`

这部分迁移已经依赖运行时占位符能力。

### tx-context
已完成第一阶段自动扫描器。

当前已映射 1 个 case：
- `ORIGIN`

当前进入 inventory 但尚未承接的包括：
- `GASPRICE`
- `BLOBHASH`

它们被延后，不是因为不能做，而是因为还需要额外的 gas-price 策略和 blob 交易构造能力。

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
项目已经从“手写少量 case”推进到“按 family 自动扫描并生成 runnable 子集”。

截至目前，已经有四个成熟或半成熟 family：
- storage
- memory
- call-context
- tx-context

其中前三个已经形成比较稳定的自动化闭环，`tx-context` 刚建立起第一阶段能力。

最近几个关键提交可以作为理解演进顺序的参考：
- `1b05017`：扩展 storage family 覆盖面。
- `9c67ce1`：加入 memory family 自动扫描器。
- `a969f68`：加入 call-context 自动扫描器。
- `4335fc6`：加入 tx-context 自动扫描器。

## 建议的后续推进顺序

### 第一优先级：account-query family
建议优先处理 `account-query` 中可直接观察结果的子集，例如：
- `SELFBALANCE`
- `CODESIZE`
- `BALANCE`

原因：
- 这类 case 仍然符合“最终状态可观测”的基本模型。
- 与当前 executor/oracle/placeholder 机制兼容性较高。
- 能进一步验证非 storage-only 语义的迁移方法。

### 第二优先级：system 中的 CALL 子集
建议接着处理 system family 里最小可表达的 external call 子集，而不是一上来处理完整 `CREATE/CREATE2/SELFDESTRUCT`。

优先承接方向：
- 单次 `CALL`
- 单次 `STATICCALL`
- 有明确最终 storage 断言的多合约交互

原因：
- 这会真正打开“跨合约调用类 case”的迁移通道。
- 当前已经具备动态地址占位符和多步执行模型，基础条件已满足。

### 第三优先级：GASPRICE 与更丰富的 tx-context
等前两步稳定后，再把 `GASPRICE` 接进来。

推荐做法：
- 明确定义真实链与 mock 链的 gas-price 观察策略。
- 把 gas-price 作为运行时上下文的一部分暴露给 oracle。

### 第四优先级：logs / receipt 类 case
可以开始迁移一批最终结果仍然稳定可观察的 case，例如：
- `LOG0..LOG4` 的 receipt/log 断言
- `contractAddress`
- `receipt_status`
- `code` 结果

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
