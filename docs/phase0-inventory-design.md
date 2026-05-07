# Phase 0：全量 inventory 实施设计

## 读者与目标
本文面向下一位要实现 Phase 0 的内部工程师。

读完后，接手人应当能够：
- 按统一模式为所有 benchmark family 建立 inventory。
- 知道哪些 CLI 命令要新增，哪些现有命令要兼容调整。
- 知道 inventory 的最小 schema 应该长什么样。
- 按低返工顺序推进实现，而不是边扫边改接口。

---

## Phase 0 的定义
Phase 0 不负责“把新 family 跑起来”，只负责先把盘子扫清楚：

> 为所有目标 benchmark family 建立稳定的 scanner 与 inventory，让项目可以量化哪些 case 已 admitted，哪些 case blocked，以及 blocked 的主因是什么。

Phase 0 的交付不是 runnable manifest，而是 **完整 inventory 账本**。

---

## 为什么要单独做 Phase 0
当前仓库已经证明了 scanner → template → manifest → run 这条路径成立，但只覆盖了四个 family：
- storage
- memory
- call-context
- tx-context

接下来如果继续直接挑 family 一个个实现，会遇到三个问题：

1. **范围不清楚**
   不知道 upstream benchmark 目录里到底还有多少可支持 case。

2. **优先级不稳定**
   很容易凭直觉挑一个 family 做，但做完才发现另一个 family 更低风险、更高复用。

3. **blocked reason 不统一**
   现有 inventory 里有不少 `not yet mapped` 风格的 reason，它们能描述实现状态，但还不能作为最终 coverage 结论。

Phase 0 的作用，就是先把这三个问题消掉。

---

## Phase 0 范围
除已接入 family 外，Phase 0 需要先为以下 benchmark instruction family 建 inventory：

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

同时，Phase 0 也要把已接入 family 的 inventory 规范化：
- `storage`
- `memory`
- `call-context`
- `tx-context`

也就是说，Phase 0 结束时，benchmark instruction 目录下所有目标 family 都必须能产出 inventory。

---

## 非目标
Phase 0 不做以下事情：

- 不要求新增 family 立刻生成 runnable manifest。
- 不要求新增 family 立刻具备 mock backend 语义。
- 不要求立即把 admitted case 渲染成模板。
- 不追求统一所有 family 的模板 renderer。

这些都属于后续阶段。

---

## 交付物
Phase 0 最低交付包括四类内容：

### 1. 每个 family 的 scanner
每个目标 family 都要能扫描 upstream 源文件，并产出：
- upstream case 标识
- case_id
- admitted / blocked
- blocked reasons
- 最小来源分类

### 2. 每个 family 的 inventory 文件
每个 family 都要有一个稳定 inventory 文件。

### 3. 覆盖率汇总命令
需要一个顶层命令，把全部 inventory 汇总成 coverage report。

### 4. blocked reason 规范
所有 inventory 的 blocked reason 必须收敛到一组稳定、能力导向的枚举，而不是临时描述。

---

## 推荐的 inventory schema
现有 inventory 已经有一个基本可用的形状。Phase 0 不建议推翻重做，建议在此基础上统一。

### family inventory 顶层
建议保持：

```json
{
  "name": "upstream-<family>-auto-inventory",
  "version": "1",
  "family": "<family>",
  "source": "third_party/execution-specs/tests/benchmark/compute/instruction/test_<family>.py",
  "entries": []
}
```
```

### 单条 entry
建议最小字段为：

```json
{
  "upstream_ref": "tests/...::test_xxx[...]",
  "case_id": "upstream.benchmark.<family>....",
  "admitted": true,
  "mode": "optional-template-mode",
  "reasons": [],
  "source": "scanner-subgroup"
}
```
```

### 字段约束
- `upstream_ref`：upstream 中的稳定定位字符串
- `case_id`：本项目内稳定 case 标识
- `admitted`：是否属于当前 harness 的可支持子集
- `mode`：如果已经能映射到模板模式，则填写；否则可为 `null`
- `reasons`：若 blocked，必须至少有一个 reason；若 admitted，应为空数组
- `source`：scanner 内部子来源，用于调试扫描逻辑，不作为最终支持边界

### 现在不要加的字段
Phase 0 不建议立即加入以下字段：
- render 细节
- expected payload
- backend-specific hints
- tx orchestration payload

这些字段更适合留给模板生成和 manifest 生成阶段。

---

## blocked reason 规范
Phase 0 的一个关键目标，是把 blocked reason 从“实现状态”收敛到“能力边界”。

建议统一使用以下集合：

- `requires genesis state`
- `requires block environment control`
- `requires trace equivalence`
- `requires precise gas fixture`
- `requires blob transaction support`
- `requires unsupported runtime observation`
- `requires unsupported multi-tx orchestration`
- `requires unsupported account or code prestate model`

### 迁移策略
对现有 reason，不要在第一步强行全改；建议按如下方式推进：

- **Phase 0 scanner 初版**：允许内部用 `not yet mapped` 类 reason 提高开发速度。
- **Phase 0 收尾**：把这些临时 reason 收敛成上面的稳定集合。
- **Phase 1 之后**：新的 inventory 不再允许增加自由文本 blocked reason，必须命中规范集合。

这样可以避免一开始为了命名争执过多，又能保证最终 coverage 结论稳定。

---

## CLI 设计

## 设计原则
1. 尽量保持现有 `scan-upstream-*` 命名模式。
2. 对已存在命令保持兼容。
3. 让“仅产 inventory”成为一等能力，而不是模板生成的附带产物。

---

## 推荐命令形状

### A. 每个 family 的 scan 命令继续保留
继续使用：
- `scan-upstream-storage`
- `scan-upstream-memory`
- `scan-upstream-call-context`
- `scan-upstream-tx-context`
- 新增其余 family 的 `scan-upstream-<family>`

### B. 参数规范统一
建议统一成：

```bash
python -m adapter.cli scan-upstream-<family> \
  --inventory-output suites/templates/upstream_<family>_inventory.json \
  [--template-output suites/templates/upstream_<family>_templates.json] \
  [--source third_party/execution-specs/tests/benchmark/compute/instruction/test_<family>.py]
```

#### 参数语义
- `--inventory-output`：**必填**
- `--template-output`：**选填**
  - 若该 family 已具备模板映射逻辑，则写出模板
  - 若当前只做 inventory，可省略
- `--source`：可选，默认指向 upstream 对应测试文件

### C. 兼容现有已接入 family
当前 4 个已接入 family 的 scan 命令要求 `--template-output`。建议在 Phase 0 中调整为：
- `--inventory-output` 必填
- `--template-output` 选填

这样可以统一命令语义：
- 所有 scan 命令都至少产 inventory
- 只有一部分 scan 命令会额外产 template

---

## 新增 coverage 汇总命令
建议新增一个顶层汇总命令，例如：

```bash
python -m adapter.cli summarize-upstream-inventory \
  --inventory-dir suites/templates \
  --output reports/upstream_inventory_summary.json
```

### 建议输出内容
至少包含：

```json
{
  "families": [
    {
      "family": "memory",
      "inventory": "upstream_memory_inventory.json",
      "total": 95,
      "admitted": 5,
      "blocked": 90,
      "blocked_reasons": {
        "requires unsupported runtime observation": 10,
        "requires precise gas fixture": 80
      }
    }
  ],
  "totals": {
    "families": 14,
    "cases": 0,
    "admitted": 0,
    "blocked": 0
  }
}
```

### 为什么单独做成命令
因为这会成为后续每个阶段的验收入口：
- Phase 0 看 inventory 是否齐
- Phase 1 看 admitted 数是否上涨
- 最终封账看 blocked 是否只剩真正能力边界

---

## 模块设计建议

## 现有模式
当前每个 family 模块大致混合了三层职责：
1. 扫描 upstream
2. 生成 template
3. 生成 manifest

这个模式对已成熟 family 没问题，但对 Phase 0 的“scan only family”会显得别扭。

## 建议拆分的逻辑层
无论是否拆文件，至少在函数层面统一为：

### 1. `scan_<family>_cases(...)`
职责：
- 读取 upstream 源文件
- 返回 inventory entries
- 若已有 admitted 模板模式，也可以顺带返回 templates

### 2. `generate_upstream_<family>_templates(...)`
职责：
- 基于 scan 结果写模板文件
- 只有已具备 template 映射的 family 才需要实现

### 3. `generate_upstream_<family>_manifest(...)`
职责：
- 从模板生成 runnable manifest
- Phase 0 可暂缺

## 建议新增共享工具层
建议新增一个共享 inventory helper 模块，负责：
- inventory payload 写盘
- blocked reason 归一化
- coverage 汇总
- family 名称 / 默认 source 规则

这样后续 family 不需要重复写顶层 JSON 包装逻辑。

---

## family 分组实施顺序
Phase 0 不建议按字母顺序做，建议按“扫描难度最低、价值最高、可快速验证模式”的顺序推进。

### 第一组：最容易归类的纯语义 family
- `arithmetic`
- `bitwise`
- `comparison`
- `stack`
- `control-flow`

原因：
- case 结构通常比较规整
- admitted / blocked 判定相对直接
- 有利于先验证 inventory 接口是否顺手

### 第二组：带观测复杂度但仍规整的 family
- `keccak`
- `account-query`
- `block-context`

原因：
- 需要更明确的 support boundary
- 但扫描规则仍相对清晰

### 第三组：高变体 family
- `log`
- `system`

原因：
- 参数维度多
- 支持边界复杂
- 更适合作为 Phase 0 后半段，等 reason 规范和 coverage 汇总都稳定后再接入

---

## 每个 family 的 Phase 0 完成标准
对单个 family，Phase 0 的“完成”指：

1. 有 `scan-upstream-<family>` 命令。
2. 命令能稳定输出 inventory。
3. inventory 中每个 case 都有：
   - `upstream_ref`
   - `case_id`
   - `admitted`
   - `reasons`
   - `source`
4. blocked reason 已归入稳定集合。
5. 有最小 unittest 覆盖：
   - scanner 能跑
   - inventory 文件结构稳定
   - admitted / blocked 计数符合预期

注意：这时 **不要求** manifest 已可运行。

---

## 测试策略
Phase 0 至少要有三类测试：

### 1. scanner 输出稳定性测试
模式与现有类似：
- 生成临时 inventory
- 与 checked-in inventory 对比

### 2. coverage 汇总测试
- 构造最小 inventory 集合
- 验证汇总命令输出的 totals 与 per-family 统计正确

### 3. blocked reason 规范测试
- 确保新 scanner 不会输出未注册的 blocked reason

---

## 推荐实施步骤

### Step 1
先把 CLI 统一改造成：
- 所有 `scan-upstream-*` 命令都支持 `--inventory-output`
- `--template-output` 改为选填

### Step 2
抽一个共享 inventory helper：
- family payload builder
- entry validator
- reason normalizer
- summary aggregator

### Step 3
先接入第一组 family：
- arithmetic
- bitwise
- comparison
- stack
- control-flow

### Step 4
实现 coverage 汇总命令，确认汇总视图可用。

### Step 5
再接入第二组和第三组 family：
- keccak
- account-query
- block-context
- log
- system

### Step 6
回头统一清理旧 inventory 的 blocked reason，把临时 reason 收敛掉。

---

## Phase 0 结束时应能回答的问题
Phase 0 完成后，项目必须可以直接回答：

1. benchmark instruction 目录里一共有多少 case。
2. 当前 harness 原则上能支持多少 case。
3. 每个 family 的 admitted / blocked 比例是多少。
4. blocked 的主因是什么。
5. 下一阶段最值得优先承接的 family 是哪个。

如果这些问题还不能直接从 inventory 和 summary 输出中回答，Phase 0 就还没完成。

---

## 执行建议
如果现在就开始做，我建议第一批提交按下面顺序拆：

1. CLI 参数统一 + inventory helper
2. coverage 汇总命令
3. 第一组 family scanner
4. 第二组 family scanner
5. 第三组 family scanner
6. reason 规范化清理

这样每一批都有明确产出，而且不会把“扫描能力建设”和“具体 family 支持实现”耦在一起。
