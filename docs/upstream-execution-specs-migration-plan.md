# execution-specs 迁移计划

## 目标
把 `execution-specs` 中能在 RPC-only、不可重置链上表达的能力，按家族逐步自动迁移到本地 harness；不能直接表达的 case 自动分类并给出过滤原因。

## 原则
- 先自动扫描，再自动分类，再自动生成模板和 manifest。
- 只承接“链上最终状态或 receipt 可证明”的 case。
- 不把 genesis / block control / trace / 精确 gas 依赖硬塞进当前 harness。
- 每个家族都要有 inventory，明确已支持、近似支持、不可支持。

## 迁移阶段

### P0 基线固化
- 固化 storage family 的自动扫描、模板生成、manifest 生成。
- 目标：新增同类 upstream case 时，不需要手工改 JSON。

### P1 storage family 扩展
- 覆盖 `SLOAD / SSTORE` 的 success / revert / out_of_gas 子分支。
- 补齐 selector、oracle、inventory 的自动分类。
- 目标：storage 家族尽量做到“自动承接 + 明确过滤”。

### P2 receipt / logs / deploy
- 覆盖 `LOG0..LOG4`、`contract creation`、`receipt_status`、`contractAddress`、`code` 断言。
- 目标：可自动迁移一批不依赖 block 控制的 receipt 类用例。

### P3 跨合约调用
- 覆盖 `CALL / STATICCALL / DELEGATECALL / CALLCODE` 的可映射子集。
- 支持多合约部署和调用编排。
- 目标：把调用类 case 从手工单例搬成批量生成。

### P4 交易上下文与序列
- 支持 `msg.value`、`caller`、`origin`、`calldata`、多笔交易序列。
- 目标：承接更多 state/transition 风格用例。

### P5 全量覆盖报告
- 输出全量 coverage inventory。
- 将 case 分成 `native-runnable`、`approx-runnable`、`not-runnable`。
- 目标：让 upstream 迁移状态可量化。

### P6 非当前 harness 能力
- 单独处理 block-level、genesis、trace、精确 gas 依赖。
- 必要时引入独立执行后端，不和当前 RPC harness 混用。

## 当前实现边界
- 已有：storage 自动扫描、模板生成、manifest 生成、selector 过滤、mock/real backend 基础。
- 待做：revert/oog 分类、logs/receipt/deploy、跨合约调用、全量 coverage inventory。

## 验收标准
- upstream 新增同类 storage case 时，扫描器能自动发现并分类。
- 不可在当前环境运行的 case 会进入 inventory，并说明原因。
- 自动生成的模板和 manifest 可重复生成，结果稳定。
- 现有回归测试保持通过。

