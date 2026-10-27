# 单一连续窗口计时

此模式用于测量完整程序主体：尽可能把加载提前到程序开头，并把原本就在最后一条
算术指令之后的写回留在计时结束之后。**窗口连续且只有一个，内部必要 IO 仍计入耗时。**
它不代表纯计算耗时，也不通过分段同步制造无 DMA 的计算区间。

## 1. 执行顺序与边界

```text
容量允许的输入、密钥、常量及 twiddle 预加载
    ↓ PSYNC，等待并确认完成
记录 start_cycles
    ↓
完整程序主体：全部算术 + 必要加载、spill/reload 和中间写回
    ↓ PSYNC，等待并确认完成
记录 end_cycles
    ↓
已有末尾写回、释放与最终同步
    ↓
按原有 golden 检查结果
```

- 预加载由真实 bank、对象容量及后续分配可行性约束；不要求整图全部数据驻留。
- 提前现有 DLOAD，不为扩大预载而新增 DMA、spill 或 reload；放不下的加载继续在主体执行。
- 全部算术都在同一窗口内，组合算子内部计算及必要 IO 一并连续计时。
- 不把全部输出写回延迟到程序末尾；只有原本位于最后一条算术之后的尾部写回被排除。
- 至多新增首尾两个 PSYNC。已有中途 PSYNC 保留，完成等待计入同一个时间窗口，不增加时间戳。

`end_cycles - start_cycles` 包含程序主体的指令发射、计算、必要 DMA 及完成等待。
边界同步和回调也有开销；实际周期由目标端采集，主机生成包不测量硬件时间。

## 2. 生成测试包

完成常规 CMake 配置后，批量生成三方案及原生算子计时包：

```sh
cmake --build build-ckks-delivery --target hpu_execution_profile_delivery -j6
```

三方案使用 N8192、Q4+P1、seed=0；原生 CMULT、NTT、INTT 使用各自 N8192 fixture。
输出位于 CMake 的 `HPU_APPLICATION_OUTPUT_ROOT`，目录后缀为 `_execution_profile`。
开启 SEAL 集成时生成六个包；未开启时生成三个原生包。

也可单独生成：

```sh
./build-ckks-delivery/hpu_ckks_evaluator_example \
  --degree 8192 --data-moduli 4 --seed 0 --profile-execution \
  --emit-dir outputs/ckks_execution_profile

./build-ckks-delivery/hpu_native_kernel_application_example \
  --case ntt --profile-execution --emit-dir outputs/native_ntt_execution_profile
```

直接写包要求目录不存在。安全重复生成使用
[应用包发布工具](../reference/HPU_SEAL_API_REFERENCE.md)，或上述 CMake 目标。
原来的 `--profile-compute` 和多窗口模式已经撤回。

自定义应用只需增加一个编译选项，构图、Evaluator 和输出标记保持原用法：

```cpp
hpu::seal_adapter::CompileOptions options;
options.profile_execution = true;
const auto compiled = app.compile("my_application", options);
compiled.write("outputs/my_application_execution_profile");
```

默认 `profile_execution=false`，普通程序入口与正常编译行为保持不变。

## 3. IT 如何执行

计时包沿用应用包 V1 的数据、指令、DMA 和 golden。IT 加载初始镜像后，编译生成的
`program/<stem>.c`，通过头文件声明的 `hpu_run_<stem>_profiled()` 调用。
示例中的 `platform_*` 是待目标环境实现的适配函数，不是本项目提供的驱动接口：

```c
#include "my_application.h"

static uint64_t read_cycles(void *user)
{
    return platform_read_monotonic_cycles(user);
}

static int wait_complete(void *user, size_t sync_index)
{
    /* 等待该次 PSYNC 完成，检查 fault，确认/清除完成事件。
       保留 SRAM 对象，不重置 HPU。失败返回非零。 */
    return platform_wait_and_ack_hpu(user, sync_index);
}

int run_profile(void *device)
{
    const hpu_execution_profile_hooks_t hooks = {
        device, read_cycles, wait_complete
    };
    hpu_execution_profile_sample_t sample;
    const int status = hpu_run_my_application_profiled(&hooks, &sample);
    if (status != 0 || !sample.valid) return status != 0 ? status : -1;
    platform_record_cycles(sample.end_cycles - sample.start_cycles);
    return 0;
}
```

时钟须单调且在两次读取间可比较。`sync_index` 从 0 开始，按实际 PSYNC 顺序递增；
等待必须对应本次完成事件，不能用残留中断或 CPU 发射结束代替硬件执行完成。
回调可以改写调用者保存寄存器，生成器会在之后的 DMA 汇编块重新设置 x10/x11。

只有包括尾部写回在内的整个程序成功完成，`sample.valid` 才为 1；任何等待失败都
中止执行，返回回调错误，样本无效。缺少参数返回 `-1`，非 RISC-V 主机返回 `-4`。
计时包的普通 `hpu_run_<stem>()`、`hpu_program_<stem>()` 返回 `-5`，防止跳过完成回调。

运行后仍按 golden manifest 读回结果。主机对拍和包校验继续执行，但不代替 RTL/板端验证。

## 4. 核对统计范围

`package.json.execution_profile_manifest` 指向 `profiling/execution_window.csv`，只有一行：

| 字段 | 含义 |
| --- | --- |
| `begin_instruction` | 主体首指令索引，起始 PSYNC 在它前一条 |
| `end_instruction` | 主体末尾的半开区间边界，该位置是结束 PSYNC |
| `arithmetic_instruction_count` | 窗口内全部算术指令数 |
| `dload_count` / `dstore_count` | 窗口内仍存在的读写次数，可以非零 |

结束时间在 `end_instruction` 位置的 PSYNC 完成后读取。
包校验器核对该范围、首尾同步、全部算术覆盖及 DMA 计数，并检查生成的 C 入口。
`oracle/report.json.execution_profile` 另记录首部 DLOAD、窗口内 DLOAD/DSTORE、尾部
DSTORE 次数及计时前正常程序的 DMA 基准。`timing_measured=false` 表示尚未采集目标周期。

需要评估正常端到端性能时，请另运行未开启计时选项的包。预加载和边界同步可能改变
IO 与计算的重叠，不能用两个包的耗时相减直接推算独立 IO 耗时。
