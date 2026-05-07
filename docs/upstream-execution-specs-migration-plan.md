# execution-specs 后续迁移计划

## 文档目的
本文面向下一位继续扩展本项目的内部工程师。

读完后，接手人应当能够：
- 理解“全部支持”在本项目里的准确定义。
- 识别当前已经形成闭环的 family、仍然半完成的 family，以及还未建 inventory 的 family。
- 按统一标准判断 upstream case 是应当承接，还是应当明确标记为 blocked。
- 按确定的阶段顺序继续推进，直到所有 **RPC-only 环境下可支持的用例** 都被本项目承接。

---

## 最终目标
本项目的目标不是把 upstream `execution-specs` 原样搬运到本地运行，而是：

> 把所有能够在 **RPC-only、不可重置、不可修改 genesis** 的链环境中，通过 **最终链上状态、receipt、logs 或运行时可捕获上下文** 证明真值的 upstream benchmark case，全部迁移到本地 harness；其余 case 一律进入 inventory，并给出稳定、能力导向的 blocked 原因。

这里的“全部支持”指的是：
- 所有 **可支持子集** 都有 scanner、inventory、template、manifest、mock 语义和回归测试。
- 所有 **不可支持子集** 都被 inventory 明确归档，而不是因为“暂时还没写”。

---

## 当前基线
截至当前仓库状态，项目已经形成四个已接入 family：

- `storage`：17 admitted / 0 blocked
- `memory`：5 admitted / 90 blocked
- `call-context`：9 admitted / 12 blocked
- `tx-context`：1 admitted / 3 blocked

其中：

### 已形成稳定闭环
- `storage`
  - 已覆盖 `SLOAD / SSTORE`
  - 已覆盖 success / revert / out_of_gas
  - 已覆盖 warm / cold 的当前可观测子集

### 已打开路径但仍未收口
- `memory`
  - 当前只覆盖 `MLOAD / MSTORE / MSTORE8 / MSIZE` 的极小子集
  - 大量 blocked case 仍属于“实现缺口”，不是能力边界
- `call-context`
  - 当前已覆盖 `ADDRESS / CALLER / CALLVALUE / CALLDATASIZE / CALLDATALOAD` 的部分矩阵
  - blocked 主要集中在更大 calldata size 和更多数据形态
- `tx-context`
  - 当前只覆盖 `ORIGIN`
  - `GASPRICE` 原则上可支持，但尚未实现
  - `BLOBHASH` 取决于 blob 交易构造能力，不属于当前默认承接范围

---

## 支持边界：什么叫“可支持用例”
后续所有 family 都按同一标准判断。一个 upstream case 只有在同时满足以下条件时，才属于本项目“最终必须支持”的范围。

### A. 真值可由最终可观测结果证明
允许使用的真值来源包括：
- storage
- balance
- code
- receipt status
- receipt contract address
- receipt logs
- 运行时可捕获上下文

### B. 不依赖 genesis 可控预置
如果 case 的正确性建立在创世状态可随意构造之上，则不属于当前 harness 承接范围。

### C. 不依赖 block-level 精确控制
如果 case 需要：
- 自定义长链历史窗口
- 精确控制 block 组装
- 精确控制 blockhash 可见窗口
- 复杂 block 环境操控
则原则上不属于当前 harness 默认承接范围。

### D. 不依赖 trace 等价或精确 gas benchmark
当前 harness 的真值是“最终可观测行为”，不是：
- trace 严格等价
- t8n 等价
- 精确 gas benchmark 对齐

---

## Blocked reason 规范
所有 scanner 产生的 inventory，后续都应统一使用能力导向的 blocked reason，而不是实现导向的临时说法。

建议统一收敛为以下几类：

- `requires genesis state`
- `requires block environment control`
- `requires trace equivalence`
- `requires precise gas fixture`
- `requires blob transaction support`
- `requires unsupported runtime observation`
- `requires unsupported multi-tx orchestration`
- `requires unsupported account or code prestate model`

在迁移早期，局部 inventory 里仍可能出现“not yet mapped”类 reason；后续应逐步把这些 reason 归并到上面的稳定集合中。

---

## 迁移原则

### 1. 先 inventory，再承接
不要先手工写 manifest；先扫全量 upstream case，明确 admitted / blocked，再决定哪些进入模板和 manifest。

### 2. 先补齐半完成 family，再开新大坑
当前最先要收口的是：
- `memory`
- `call-context`
- `tx-context`

### 3. 先建设通用原语，再批量扩 family
后续如果继续为每个 family 手写一套 bytecode hex 和观测逻辑，成本会迅速失控。应优先抽出：
- 通用 probe contract 模板
- 通用 runtime context 占位符
- 通用 receipt/log 观测面

### 4. 以“可支持子集全覆盖”为准，不以“文件存在”为准
某个 family 建了 scanner 还不算完成；只有当它的 admitted case 全部可运行、可验证、可回归时，才算完成。

---

## 总体阶段路线图

## Phase 0：建立全量 inventory 账本
### 目标
先知道总盘子有多大，再谈“全部支持”。

### 要做什么
为尚未接入的 benchmark family 建立 scanner 和 inventory：
- `account-query`
- `arithmetic`
- `bitwise`
- `comparison`
- `control-flow`
- `keccak`
- `log`
- `block-context`
- `stack`
- `system`

### 产出
- 每个 family 都有全量 inventory
- 顶层 coverage 报告，至少包含：
  - family
  - total
  - admitted
  - blocked
  - blocked reason breakdown

### 完成标准
- benchmark instruction 目录下的所有目标 family 都有 inventory
- 后续不再靠人工猜测哪些 case 可能支持

---

## Phase 1：补齐已接入但未收口的 family
### 目标
先把已经验证过路线可行的 family 收口。

### 1. memory
应继续扩展到所有仍满足“最终可观测”模型的子集，重点包括：
- `MLOAD`
- `MSTORE`
- `MSTORE8`
- `MSIZE`

优先补当前 blocked 的矩阵维度：
- offset 的更多位置
- initialized / uninitialized 组合
- 更大的 memory size 配置
- 能在最终状态中稳定观察到的 memory expansion 结果

### 2. call-context
补齐：
- `CALLDATASIZE` 更完整矩阵
- `CALLDATALOAD` 更完整矩阵
- 清理当前 scanner 中异常的空 opcode case

### 3. tx-context
新增：
- `GASPRICE`

继续 blocked：
- `BLOBHASH`，直到 harness 真正具备 blob 交易构造与观测能力

### 完成标准
- `memory / call-context / tx-context` 中所有仍可由最终状态或上下文证明的 case 全部 admitted
- inventory 中剩余 blocked case 都是能力边界，而不是实现缺口

---

## Phase 2：建设通用 probe / 观测 / 占位符原语
### 目标
为后续批量迁移更多 family 降低边际成本。

### 应新增的通用能力

#### A. 更通用的 probe 合约生成方式
从“每个 family 手写 bytecode hex”逐步过渡到可组合的最小模板：
- setup
- attack block
- persist-to-storage
- optional call wrapper
- optional return-data wrapper

#### B. 更丰富的 runtime context 占位符
在现有：
- `$last_contract_word`
- `$admin_account_word`

基础上，逐步增加：
- `$gas_price`
- `$block_number`
- `$block_timestamp`
- `$block_coinbase`
- `$block_prev_randao`
- `$chain_id`
- `$base_fee`
- 与 logs / receipt 相关的运行时上下文占位符

#### C. 更丰富的 executor 观测面
当前主要观测：
- storage
- code
- balance
- receipt status
- receipt contract address

后续要补：
- receipt logs
- topic values / topic count
- data hash / data length
- 更稳定的运行时上下文捕获

### 完成标准
- 新增 family 时，不再需要复制大量 family-specific 执行模板
- oracle / executor 足以支撑 account-query、block-context、log、system 子集

---

## Phase 3：批量承接低风险纯语义 family
### 目标
优先扫清那些不依赖复杂链环境、只需把 opcode 结果稳定写回 storage 的 family。

### 范围
- `arithmetic`
- `bitwise`
- `comparison`
- `stack`
- `control-flow`
- `keccak`

### 承接策略
不追求复刻 upstream 的 gas-worst-case benchmark 形状，而是承接其中可被最终状态证明的语义子集：
- 算术结果写入 storage
- 位运算结果写入 storage
- 比较结果写入 storage
- stack 变换最终落到 storage
- control flow 的最终路径结果落到 storage
- keccak 的输出或输出摘要写入 storage

### 风险控制
若某些 upstream case 的主要价值仅在 gas 压力形状而非语义结果，则应进入 blocked inventory，并说明原因，不强行近似实现。

### 完成标准
- 上述 family 均具备 scanner、inventory、template、manifest、mock backend 语义与回归测试
- supportable 子集全部 admitted

---

## Phase 4：承接账户 / 区块 / 日志 family
### 目标
把非 storage-only 但仍然可观测的 family 吃下来。

### 1. account-query
优先级高，且与现有 executor / oracle 兼容性最好。

建议分两批承接：

#### 第一批
- `SELFBALANCE`
- `CODESIZE`
- `BALANCE`

#### 第二批
- `EXTCODESIZE`
- `EXTCODEHASH`
- `CODECOPY`
- `EXTCODECOPY`

其中 `CODECOPY / EXTCODECOPY` 不应直接对整段 memory 做脆弱断言，建议把：
- size
- 首尾 word
- 哈希摘要
- 关键切片
写回 storage 后再断言。

### 2. block-context
建议承接的零参数 opcode：
- `COINBASE`
- `TIMESTAMP`
- `NUMBER`
- `PREVRANDAO`
- `GASLIMIT`
- `CHAINID`
- `BASEFEE`

条件承接：
- `BLOBBASEFEE`，仅在 profile 能确认底层链支持相关特性时 admitted

原则上继续 blocked：
- `BLOCKHASH`，因为它依赖链历史窗口和 block-level 控制

### 3. log
承接：
- `LOG0`
- `LOG1`
- `LOG2`
- `LOG3`
- `LOG4`

真值来源应转向：
- receipt logs
- topic count
- topic values
- data hash / size

### 完成标准
- `account-query / block-context / log` 均有完整 inventory
- admitted 子集能在 mock 和 jsonrpc 两个 backend 上闭环验证

---

## Phase 5：承接 system family 的可支持子集
### 目标
最后处理最复杂但价值最高的一批。

### 承接顺序

#### 第一批：单次 external call 子集
- `CALL`
- `STATICCALL`
- `CALLCODE`
- `DELEGATECALL`

仅承接以下可稳定证明的 case：
- 有明确最终 storage 断言
- 可从 caller / callee 上下文中提取真值
- revert / success 可通过 receipt 和持久化结果断言

#### 第二批：`RETURN / REVERT`
通过 caller-wrapper 合约把：
- success / failure
- returndata size
- returndata 首 word 或哈希
写回 storage 后断言。

#### 第三批：`CREATE / CREATE2`
只承接可稳定证明的子集，例如：
- contract address
- code
- receipt status
- deterministic address
- 最小 collision 场景

#### 第四批：`SELFDESTRUCT`
严格按当前链语义收窄，只承接在目标链上语义稳定、真值明确、不会依赖历史 EVM 语义分歧的子集。

### 原则上不作为当前默认目标的 system case
- 强依赖 gas-driven many-address benchmark 形状的 case
- 必须依赖 block 组织或长链 setup 的 case
- 必须依赖 trace 或精确 gas 模型的 case

### 完成标准
- `system` family 中所有 supportable 子集 admitted
- 剩余 blocked case 的原因稳定、可复现、非实现缺口

---

## Phase 6：覆盖率封账
### 目标
证明“所有可支持用例都已支持”，而不是主观宣称完成。

### 要做什么
1. 为全部 benchmark family 生成总 coverage 报告。
2. 对每个 family 输出：
   - total
   - admitted
   - blocked
   - blocked reasons
3. 对 blocked case 做最终归类：
   - genuinely unsupported in current RPC harness
   - requires blob-capable backend
   - requires block-control backend
   - requires trace backend
   - requires genesis/prestate backend

### 何时可以宣布完成
当同时满足以下三条时，可以说：

> 本项目已经覆盖了 execution-specs benchmark family 中，所有在当前 RPC-only harness 模型下可支持的用例。

判定标准：
1. 所有目标 family 都已有 inventory。
2. 所有 admitted case 都有 runnable manifest 与回归测试。
3. 所有 blocked case 都有稳定、能力导向的原因，而不是“以后再说”。

---

## 推荐的实际执行顺序
基于当前仓库状态，推荐按以下顺序推进：

1. **Phase 0：全量 inventory**
2. **Phase 1：收口 `memory / call-context / tx-context`**
3. **Phase 2：通用 probe / 观测 / 占位符原语**
4. **Phase 3：`arithmetic / bitwise / comparison / stack / control-flow / keccak`**
5. **Phase 4：`account-query / block-context / log`**
6. **Phase 5：`system`**
7. **Phase 6：coverage 封账**

这个顺序的原因是：
- `storage` 已经完成，不应继续作为主战场。
- `memory / call-context / tx-context` 的 blocked 大多是实现缺口，优先补齐收益最高。
- 纯语义 family 风险低、可复用性高，适合在通用原语到位后批量推进。
- `system` 风险最高，最适合放在最后，避免过早把执行模型复杂化。

---

## 每个新 family 的最低交付清单
后续不论处理哪个 family，都必须同时补齐以下内容：

1. scanner
2. inventory
3. template 生成
4. manifest 生成
5. mock backend 语义
6. jsonrpc backend 所需观测面
7. unittest 回归

如果缺任一项，就不应视为该 family 已接入。

---

## 下一步建议
如果下一位接手人从当前状态继续推进，建议第一步直接做：

1. 为尚未接入的 benchmark family 建立 inventory。
2. 立刻收口 `memory / call-context / tx-context`。
3. 在此过程中抽出通用 probe / 观测原语，为后续大规模扩面做准备。

这三步完成后，项目才算从“证明路径可行”真正进入“系统化收口所有可支持用例”的阶段。
