# HPU-FHE语义模拟器

`tools/hpu_fhe_semantic_sim`是一套独立Python3标准库程序。它直接解码`.inst32`，顺序执行当前11条HPU指令，并同时输出DDR物理内容和自然逻辑顺序的FHE数学结果。

模型声明固定为：

```text
model=SEMANTIC_MODEL
arithmetic=EXACT_MOD_Q
timing=SEQUENTIAL_ARCHITECTURAL
```

程序覆盖`padd/psub/pmul/pmac/pntt/pintt/pmodld/pfree/psync/dload/dstore`。PNTT执行`load→64-lane BF→P→store`；PINTT执行`load→P^-1→64-lane BF→store`。首版只接受`mode=0,flag=0`的PNTT/PINTT语义。

主分支完成重构后，正式数据的唯一来源是同一次`hpu_delivery`生成的
`outputs/<case>/`交付包。语义模拟器不会为正式包重新选择模数、重新生成twiddle，
也不会二次分配DDR。原来的`prepare`命令保留为独立语义单测的synthetic模式。

## 1.命令

### 1.1校验主分支交付包（正式接入方式）

```bash
python3 -m tools.hpu_fhe_semantic_sim validate-delivery \
  --case-dir outputs/mm
```

该命令直接读取并交叉检查`params.json`、`abi.json`、`hpu_mem_config.json`、
`line_map.csv`、`mod_ctx_map.csv`、可选`twiddle_map.csv`、HPU_MEM镜像、
`.inst32/.cmd26`和`dma_relocation_manifest.csv`。硬件manifest中的
`readable_path`由主分支决定，当前为`.u32.dec.txt`，接收端不写死展示文件后缀。
它只校验交付包结构、跨文件ABI一致性、机器码可解码性和可选DMA绑定；不会执行
`.inst32`指令流，也不会把运行结果与`expected`/golden逐字比较。执行与结果比较必须
另行构造resolved case后使用`run`，或由目标RTL/板级环境完成。

`dma_relocation_manifest.csv`只说明某条DMA的指令字段，不说明它应绑定哪个数据对象。
因此模拟器不会按文件名或role猜测，调用方必须显式提供逐DMA映射：

```json
{
  "format_version": 1,
  "assignments": [
    {"dma_index": 0, "artifact_path": "constants/mod_ctx.u32.bin", "artifact_line_offset": 0, "line_count": 1, "domain": "mod_ctx"},
    {"dma_index": 1, "artifact_path": "images/input_a.u32.bin", "artifact_line_offset": 0, "line_count": 64, "domain": "ntt_physical"},
    {"dma_index": 2, "artifact_path": "images/input_b.u32.bin", "artifact_line_offset": 0, "line_count": 64, "domain": "ntt_physical"},
    {"dma_index": 3, "artifact_path": "images/expected.u32.bin", "artifact_line_offset": 0, "line_count": 64, "domain": "ntt_physical"}
  ]
}
```

```bash
python3 -m tools.hpu_fhe_semantic_sim validate-delivery \
  --case-dir outputs/mm \
  --assignments mm.assignments.json
```

`artifact_line_offset`是artifact内部的相对line偏移，`line_count`是本次x11值；
因此一个包含多个RNS limb或多个stage的大文件可以被不同DMA显式切片，接收端不会把
整个文件误当成单次传输。两者都必须落在`line_map.csv`声明的artifact范围内。
普通对象单次最多1024 lines；`type=2,flag=1`的mod-context DLOAD必须绑定完整的
`constants/mod_ctx.u32.bin`，且不得超过small bank的32 lines。

不带映射时状态为`VALID_UNRESOLVED`；带完整且匹配的映射时为
`VALID_RESOLVED`。缺失、额外、重复、越界或与机器码不一致的映射都会失败关闭。

`outputs/{ckks_encode,bgv_encode,bfv_encode}`是纯host Encode/Decode包，不包含
`hardware/`、`.inst32/.cmd26`或DMA relocation，因此不属于`validate-delivery`的
输入范围；它们的host数学自检属于主构建测试，不应报告为本命令已校验。不存在旧的
单一`outputs/encode`目录。

### 1.2准备synthetic case（模型单测方式）

```bash
python3 -m tools.hpu_fhe_semantic_sim prepare \
  --case case.json \
  --output-dir runs/example/input
```

`prepare`只为独立模型测试完成以下工作：

- 读取现有inline-asm生成的`.inst32`和可选`.cmd26`。
- 自动生成或读取外部little-endian`uint32`输入。
- 自动搜索满足`q≡1(mod2N)`的素数并验证primitive`2N`th root。
- 生成`q32+mu48+reserved48`模上下文。
- 为synthetic NTT/INTT生成pre/postfactor和每stage固定`N/2`个物理twiddle。
- 将自然序输入转换到coefficient bit-reversed或NTT physical layout。
- 按256Bline自动分配DDR，并用`0xA5A5A5A5`填充DSTORE目标span。
- 输出resolvedcase、输入manifest、DDR镜像和逐DMA绑定。

正式delivery若`abi.json`声明`twiddle_images_included=false`，读取层要求
`twiddle_map.csv`不存在；只有实际使用PNTT/PINTT的交付包才接收twiddle数据。

### 1.3执行完整程序

```bash
python3 -m tools.hpu_fhe_semantic_sim run \
  --case runs/example/input/case_resolved.json \
  --output-dir runs/example/output
```

需要完整hex文本时增加：

```bash
--emit-full-hex
```

### 1.4执行单条指令

```bash
python3 -m tools.hpu_fhe_semantic_sim step \
  --state state.json \
  --inst32 0x0400400B \
  --output-dir runs/padd_step
```

也可直接传入汇编文本：

```bash
python3 -m tools.hpu_fhe_semantic_sim step \
  --state state.json \
  --asm "padd p2, p0, p1" \
  --output-dir runs/padd_step_asm
```

单步DLOAD/DSTORE时，`state.json`还要提供`memory.image`和一条完整`binding`；输出目录下的`ddr/ddr_before.u32.bin`与`ddr/ddr_after.u32.bin`记录该次DMA的物理效果。

`step`状态文件通过路径引用大对象：

```json
{
  "schema_version": 1,
  "N": 4096,
  "active_context": {
    "mod_id": 0,
    "q": 50061313,
    "mu": 368483025479
  },
  "objects": [
    {
      "slot": 0,
      "path": "input_a.u32.bin",
      "data_type": 1,
      "domain": "coefficient",
      "role": "left"
    },
    {
      "slot": 1,
      "path": "input_b.u32.bin",
      "data_type": 1,
      "domain": "coefficient",
      "role": "right"
    }
  ]
}
```

上例中的q和mu只展示字段格式。正式case应使用`prepare`生成值或硬件团队提供的实际上下文。

### 1.5比较两份trace

```bash
python3 -m tools.hpu_fhe_semantic_sim compare \
  --left runs/local/trace.jsonl \
  --right runs/song/trace.jsonl
```

比较器检查instruction index、DMAindex、机器码、助记符、活动模数、变更对象、DDRspan和状态，并报告首条差异记录。完整数值正确性由stage checkpoint和最终逐word结果比较负责。

## 2.case配置

最小配置字段如下：

```json
{
  "schema_version": 1,
  "case_name": "pmul_generated",
  "operation": "pmul",
  "N": 4096,
  "seed": 20260825,
  "program": {
    "inst32": "program.inst32"
  },
  "memory": {
    "line_bytes": 256,
    "line_count": "auto"
  },
  "moduli": {
    "source": "generated",
    "count": 1
  },
  "inputs": [
    {
      "name": "left",
      "source": "generated",
      "shape": [4096],
      "domain": "coefficient",
      "modulus_index": 0
    },
    {
      "name": "right",
      "source": "generated",
      "shape": [4096],
      "domain": "coefficient",
      "modulus_index": 0
    }
  ],
  "dma_bindings": [
    {
      "instruction_index": 0,
      "direction": "dload",
      "obj_id": 4,
      "type_or_release": 2,
      "flag": 1,
      "artifact": "mod_contexts"
    },
    {
      "instruction_index": 2,
      "direction": "dload",
      "obj_id": 0,
      "type_or_release": 1,
      "flag": 0,
      "artifact": "left"
    },
    {
      "instruction_index": 3,
      "direction": "dload",
      "obj_id": 1,
      "type_or_release": 1,
      "flag": 0,
      "artifact": "right"
    },
    {
      "instruction_index": 7,
      "direction": "dstore",
      "obj_id": 2,
      "type_or_release": 1,
      "flag": 0,
      "artifact": "output:product",
      "payload_words": 4096
    }
  ],
  "checkpoint_policy": "trace_and_changed_spans"
}
```

`inputs[].source`支持：

- `generated`：使用seed生成canonicalresidue，开头固定覆盖`0/1/q-1`。
- `file`：读取`inputs[].path`，并严格检查shape、字节数和`0<=word<q`。

`memory.line_count`支持`auto`或显式正整数。显式窗口必须容纳所有输入、常量、scratch和输出span。

## 3.NTT/INTT绑定token

NTTcase可以在`dma_bindings[].artifact`中引用：

```text
mod_contexts
输入name
ntt_pre_twist
ntt_stage_0 ... ntt_stage_logN-1
intt_stage_0 ... intt_stage_logN-1
intt_post_factor
output:结果name
```

每个stage对象包含`N/2`个`uint32`twiddle。执行器直接消费DDR加载的实际twiddle；独立逻辑oracle使用q和psi计算自然序expected。

## 4.DDR和结果文件

`run`输出：

```text
ddr_before.u32.bin
ddr_after.u32.bin
ddr_diff.csv
trace.jsonl
summary.json
dstore/dma_*.u32.bin
checkpoints/pntt_stage_*.u32.bin
checkpoints/pintt_stage_*.u32.bin
physical/final_result.u32.bin
logical/actual_from_physical.u32.bin
logical/final_result.u32.bin
logical/final_result.preview.hex.txt
mapping/physical_to_logical.csv
```

含义如下：

- `ddr_before`保留输入DDR快照。
- `ddr_after`是DLOAD/DSTORE顺序执行后的完整工作DDR。
- `ddr_diff.csv`逐word记录所有变化，包含line offset和line内word位置。
- `physical/final_result`是最后一个DSTORE的物理数据。
- `logical/actual_from_physical`是根据domain和layout转换后的实际逻辑数据。
- `logical/final_result`是独立FHE数学oracle结果。
- `mapping/physical_to_logical.csv`记录每个物理word对应的逻辑系数。
- `summary.json`给出DDR大小、变化word数量、结果word数量和首个差异。

每条trace包含机器码、解码字段、活动MOD_ID/q、live对象、变更对象、变更span、DDRspan、stage信息和状态。

## 5.数据规模和安全规则

- DDR工作镜像使用`mmap`。
- DDR复制和逐word diff按4MiB分块。
- 多项式对象使用`array('I')`。
- 不创建完整DDR的Python整数列表。
- 输出目录必须为全新路径。
- 程序不覆盖已有输出，不执行目录递归删除，不自动清理失败产物。
- DSTORE目标在prepare阶段填充poison，expected独立保存。
- DLOAD读取当前`ddr_after`，可以观察此前DSTORE写入的scratch。
- 运行测试时应将`TMPDIR`指向磁盘目录；单测使用独立临时目录并在结束时清理。

## 6.能力边界

首版提供架构完成点上的顺序功能语义。以下项目继续由独立资格验证覆盖：

- PE内部48-bitmu、33-bit`q_hat`和修正路径的bit-exact中间值。
- DMA并发、busy持续时间、队列backpressure和周期数。
- allocator实际Bank/base选择。
- cache、FAULT、IRQ和板级一致性。

非零PNTT/PINTTmode/flag、歧义模表、非法span、对象长度不匹配、非canonicalresidue和生命周期错误均失败关闭，并输出结构化首错信息。

## 7.验证

独立Python测试：

```bash
python3 -B -m unittest discover -s test/semantic -p 'test_*.py'
```

CTest入口：

```bash
cmake -S . -B build -DBUILD_TESTING=ON
ctest --test-dir build -R '^hpu_semantic_' --output-on-failure
```

测试覆盖11条机器码解码、算术边界、MB级mmap跨4MiB检查、DMA状态、PNTT/PINTT单stage、完整硬件roundtrip、negacyclicconvolution、prepare→run的PMUL链路和完整N=128NTT链路。
