#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# gen_ntt_run_data.py — NTT 运行数据导出包生成器（2026-09-10）
#
# 数据源两部分：
#   Part A：3 个 NTT tc 的单级 slice 数据（golden model 公式已于 2026-09-09 用 RTL
#           ddr_dump ground truth 反解验证 512/512 word 逐字命中）
#           - tc_pipeline_pntt_slice   : PNTT stage0（真实 twiddle）
#           - tc_pipeline_pintt_slice  : PINTT stage0（W=1 bypass）+ stage1（真实 twiddle）
#           - tc_full_pipeline_pintt   : PINTT stage0（与 pintt_slice stage0 同场景）
#   Part B：doc/hw_ntt_intt_complete.py（设计师 golden model）完整多级正向 NTT N=512
#           参考：每级 loader batch / 旋转因子 / BF 运算 / 级后存储状态 + INTT 旋转因子表
#
# 运行：/usr/bin/python3.12 gen_ntt_run_data.py   （在 doc/ntt_run_data/ 下执行）
import csv
import os
import random
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.dirname(HERE)
SIM = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(DOC))),
                   "ver_ws", "ver", "ut", "hpu_top", "sim")
sys.path.insert(0, DOC)

Q_TC = 0xFFFFFFFE          # tc 场景模数（q = 2^32-2，Barrett mu = 0x1_0000_0002）
DDR_BASE = 0x142000        # HPU_MEM window 基址（CSR 0x00=0x0014_2000）
ROW = 256                  # 指令 cmd_mem_line_offset 单位 = 256B row = 8 DDR lines
ACT_PNTT = "/tmp/act_pntt_slice.txt"    # tc_pipeline_pntt_slice   实测 dump（64 lines）
ACT_PINTT = "/tmp/act_pintt_slice.txt"  # tc_pipeline_pintt_slice  实测 dump（128 lines）

os.chdir(HERE)


def wcsv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def parse_dump(path):
    """ddr_dump.txt -> {line_addr: [w0..w7]}（%0h 丢前导零须 zfill，MSB-first 反转）"""
    out = {}
    for row in open(path):
        parts = row.split()
        h = parts[1].zfill(64)
        out[int(parts[0], 16)] = [int(h[i * 8:(i + 1) * 8], 16) for i in range(8)][::-1]
    return out


def obj_rows(base_off_rows, val_fn, n=512):
    """对象 512 word 行：word_idx/line/word_in_line/DDR 地址/值"""
    return [(w, w >> 3, w & 7,
             DDR_BASE + base_off_rows * ROW + (w >> 3) * 32 + (w & 7) * 4,
             val_fn(w)) for w in range(n)]


OBJ_HDR = ["word_idx", "line", "word_in_line", "ddr_addr", "value"]
INSTR_HDR = ["seq", "cmd_bits", "instruction", "obj_id/pdst", "psrc1", "psrc2",
             "stage_id", "ddr_offset_rows", "ddr_base_addr", "len_rows",
             "data_file", "note"]
OUT_HDR = ["word_idx", "line", "word_in_line", "ddr_addr", "expected", "rtl_act", "match"]
BF_HDR = ["iter", "lane", "a_src", "b_src", "t_src", "pe_a", "pe_b", "twiddle_T",
          "out0", "out1", "out0_dst_word", "out1_dst_word"]


def modq(v):
    return v % Q_TC


# ============ Part A.1: tc_pipeline_pntt_slice（PNTT stage0） ============
def gen_pntt_slice():
    d = os.path.join(HERE, "tc_pipeline_pntt_slice")
    os.makedirs(d, exist_ok=True)

    wcsv(f"{d}/instructions.csv", INSTR_HDR, [
        [1, "0x2000000", "DLOAD  obj0", 0, "-", "-", "-", 0, hex(DDR_BASE), 8,
         "obj0_poly.csv", "custom1 dload，poly 数据 {8{0x100|L}}/line"],
        [2, "0x2040000", "DLOAD  obj1", 1, "-", "-", "-", 8, hex(DDR_BASE + 8 * ROW), 8,
         "obj1_twiddle.csv", "twiddle 数据 {8{0x200|L}}/line"],
        [3, "0x0880080", "PNTT", 2, 0, 1, 0, "-", "-", "-",
         "pntt_stage0_bf_ops.csv", "custom0 opc=4，outplace，ntt_alloc 自然分配 obj2"],
        [4, "0x2080020", "DSTORE obj2", 2, "-", "-", "-", 16, hex(DDR_BASE + 16 * ROW), 8,
         "obj2_output_exp_vs_rtl.csv", "NTT 结果 64 lines 全量回读比对"],
    ])

    poly = lambda w: 0x100 | (w >> 3)
    twd = lambda w: 0x200 | (w >> 3)
    wcsv(f"{d}/obj0_poly.csv", OBJ_HDR, obj_rows(0, poly))
    wcsv(f"{d}/obj1_twiddle.csv", OBJ_HDR, obj_rows(8, twd))

    # BF 运算级：batch b（=py 正向 s=0 的 128-word 顺序窗）× lane l
    bf, exp = [], [0] * 512
    for b in range(4):
        for l in range(64):
            aw, bw_, tw = 128 * b + 2 * l, 128 * b + 2 * l + 1, 64 * b + l
            A, B, T = poly(aw), poly(bw_), twd(tw)
            o0, o1 = modq(A + B * T), modq(A - B * T)
            bf.append([b, l, aw, bw_, tw, A, B, T, o0, o1,
                       128 * b + l, 128 * b + 64 + l])
            exp[128 * b + l] = o0
            exp[128 * b + 64 + l] = o1
    wcsv(f"{d}/pntt_stage0_bf_ops.csv", BF_HDR, bf)

    act = parse_dump(ACT_PNTT)
    rows, bad = [], 0
    for w in range(512):
        a = act[0xA180 + (w >> 3)][w & 7]
        ok = (a == exp[w])
        bad += 0 if ok else 1
        rows.append([w, w >> 3, w & 7,
                     DDR_BASE + 16 * ROW + (w >> 3) * 32 + (w & 7) * 4,
                     exp[w], a, ok])
    wcsv(f"{d}/obj2_output_exp_vs_rtl.csv", OUT_HDR, rows)
    shutil.copy(ACT_PNTT, f"{d}/rtl_act_dump.txt")
    assert bad == 0, f"pntt_slice golden vs RTL mismatch {bad}"
    return f"tc_pipeline_pntt_slice: BF ops {len(bf)} 行，输出 512/512 word 与 RTL 实测一致"


# ============ Part A.2: tc_pipeline_pintt_slice（PINTT stage0 + stage1） ============
def pintt_s0_word(w):
    is1 = w >= 256
    ww = w & 255
    k, l = ww >> 6, ww & 63
    al = (8 * k if (l & 1) == 0 else 32 + 8 * k) + (l >> 4)
    A, B = 0x100 + al, 0x100 + al + 4
    return modq(A - B) if is1 else modq(A + B)   # W=1 bypass


def pintt_s1_word(w):
    q4 = w >> 6
    is1 = (q4 >> 1) & 1
    k = (q4 & 1) | ((q4 >> 2) << 1)
    l = w & 63
    base = 8 * (k & 1) + 32 * (k >> 1)
    al = (base if (l & 1) == 0 else 16 + base) + (l >> 4)
    A, B, T = 0x100 + al, 0x100 + al + 4, 0x200 + 8 * k + (l >> 3)
    return modq(A - B * T) if is1 else modq(A + B * T)


def gen_pintt_slice():
    d = os.path.join(HERE, "tc_pipeline_pintt_slice")
    os.makedirs(d, exist_ok=True)

    wcsv(f"{d}/instructions.csv", INSTR_HDR, [
        [1, "0x2000000", "DLOAD  obj0", 0, "-", "-", "-", 0, hex(DDR_BASE), 8,
         "obj0_polyA.csv", "poly_A（stage0 输入）"],
        [2, "0x2040000", "DLOAD  obj1", 1, "-", "-", "-", 8, hex(DDR_BASE + 8 * ROW), 8,
         "obj1_polyB.csv", "poly_B（stage1 输入 + stage0 psrc2 占位）"],
        [3, "0x2100000", "DLOAD  obj4", 4, "-", "-", "-", 32, hex(DDR_BASE + 32 * ROW), 8,
         "obj4_twiddle.csv", "twiddle（stage1 用）"],
        [4, "0x0A80080", "PINTT stage0", 2, 0, 1, 0, "-", "-", "-",
         "intt_stage0_bf_ops.csv", "twiddle_one_bypass W=1（rd2 不读）"],
        [5, "0x0AC8208", "PINTT stage1", 3, 1, 4, 1, "-", "-", "-",
         "intt_stage1_bf_ops.csv", "真实 twiddle 读取（rd2=obj4）"],
        [6, "0x2080020", "DSTORE obj2", 2, "-", "-", "-", 16, hex(DDR_BASE + 16 * ROW), 8,
         "obj2_stage0_output_exp_vs_rtl.csv", "stage0 结果 64 lines 回读"],
        [7, "0x20C0020", "DSTORE obj3", 3, "-", "-", "-", 24, hex(DDR_BASE + 24 * ROW), 8,
         "obj3_stage1_output_exp_vs_rtl.csv", "stage1 结果 64 lines 回读"],
    ])

    poly = lambda w: 0x100 | (w >> 3)
    twd = lambda w: 0x200 | (w >> 3)
    wcsv(f"{d}/obj0_polyA.csv", OBJ_HDR, obj_rows(0, poly))
    wcsv(f"{d}/obj1_polyB.csv", OBJ_HDR, obj_rows(8, poly))
    wcsv(f"{d}/obj4_twiddle.csv", OBJ_HDR, obj_rows(32, twd))

    # stage0 BF 表：iter k × lane l；T=1 bypass；源 line 级（preload 每 line 8 word 同值）
    bf0 = []
    for k in range(4):
        for l in range(64):
            al = (8 * k if (l & 1) == 0 else 32 + 8 * k) + (l >> 4)
            A, B = 0x100 + al, 0x100 + al + 4
            bf0.append([k, l, f"line {al}", f"line {al + 4}", "bypass(W=1)",
                        A, B, 1, modq(A + B), modq(A - B), 64 * k + l, 256 + 64 * k + l])
    wcsv(f"{d}/intt_stage0_bf_ops.csv", BF_HDR, bf0)

    # stage1 BF 表：out0 基址 {0,64,256,320}[k]，out1 = out0+128
    bf1 = []
    for k in range(4):
        base = 8 * (k & 1) + 32 * (k >> 1)
        for l in range(64):
            al = (base if (l & 1) == 0 else 16 + base) + (l >> 4)
            tl = 8 * k + (l >> 3)
            A, B, T = 0x100 + al, 0x100 + al + 4, 0x200 + tl
            d0 = {0: 0, 1: 64, 2: 256, 3: 320}[k] + l
            bf1.append([k, l, f"line {al}", f"line {al + 4}", f"line {tl}",
                        A, B, T, modq(A + B * T), modq(A - B * T), d0, d0 + 128])
    wcsv(f"{d}/intt_stage1_bf_ops.csv", BF_HDR, bf1)

    act = parse_dump(ACT_PINTT)
    for name, fn, act_base, off in (("stage0", pintt_s0_word, 0xA180, 16),
                                    ("stage1", pintt_s1_word, 0xA1C0, 24)):
        exp = [fn(w) for w in range(512)]
        rows, bad = [], 0
        for w in range(512):
            a = act[act_base + (w >> 3)][w & 7]
            ok = (a == exp[w])
            bad += 0 if ok else 1
            rows.append([w, w >> 3, w & 7,
                         DDR_BASE + off * ROW + (w >> 3) * 32 + (w & 7) * 4,
                         exp[w], a, ok])
        wcsv(f"{d}/obj{'2' if name == 'stage0' else '3'}_{name}_output_exp_vs_rtl.csv",
             OUT_HDR, rows)
        assert bad == 0, f"pintt_slice {name} mismatch {bad}"
    shutil.copy(ACT_PINTT, f"{d}/rtl_act_dump.txt")
    return (f"tc_pipeline_pintt_slice: stage0 BF {len(bf0)} 行 / stage1 BF {len(bf1)} 行，"
            f"双 stage 各 512/512 word 与 RTL 实测一致")


# ============ Part A.3: tc_full_pipeline_pintt（PINTT stage0） ============
def gen_full_pipeline_pintt():
    d = os.path.join(HERE, "tc_full_pipeline_pintt")
    os.makedirs(d, exist_ok=True)

    wcsv(f"{d}/instructions.csv", INSTR_HDR, [
        [1, "0x2000000", "DLOAD  obj0", 0, "-", "-", "-", 0, hex(DDR_BASE), 8,
         "obj0_poly.csv", "poly 数据"],
        [2, "0x2040000", "DLOAD  obj1", 1, "-", "-", "-", 8, hex(DDR_BASE + 8 * ROW), 8,
         "-", "dummy（PINTT stage0 绕过 rd2，但 controller 仍需 obj1 valid）"],
        [3, "0x0A80080", "PINTT stage0", 2, 0, 1, 0, "-", "-", "-",
         "intt_stage0_bf_ops.csv", "twiddle_one_bypass W=1"],
        [4, "0x2080020", "DSTORE obj2", 2, "-", "-", "-", 16, hex(DDR_BASE + 16 * ROW), 8,
         "obj2_output_golden.csv", "回归 64/64 lines match（场景与 pintt_slice stage0 一致）"],
    ])

    poly = lambda w: 0x100 | (w >> 3)
    wcsv(f"{d}/obj0_poly.csv", OBJ_HDR, obj_rows(0, poly))

    bf = []
    for k in range(4):
        for l in range(64):
            al = (8 * k if (l & 1) == 0 else 32 + 8 * k) + (l >> 4)
            A, B = 0x100 + al, 0x100 + al + 4
            bf.append([k, l, f"line {al}", f"line {al + 4}", "bypass(W=1)",
                       A, B, 1, modq(A + B), modq(A - B), 64 * k + l, 256 + 64 * k + l])
    wcsv(f"{d}/intt_stage0_bf_ops.csv", BF_HDR, bf)

    rows = [[w, w >> 3, w & 7,
             DDR_BASE + 16 * ROW + (w >> 3) * 32 + (w & 7) * 4, pintt_s0_word(w)]
            for w in range(512)]
    wcsv(f"{d}/obj2_output_golden.csv", OBJ_HDR, rows)
    return ("tc_full_pipeline_pintt: BF ops 256 行，输出 512 word golden"
            f"（本 tc 无 raw dump phase，实测 PASS 依据回归 log 64/64 lines match）")


# ============ Part B: py golden model 完整多级正向 NTT（N=512） ============
def gen_py_full_ntt():
    import hw_ntt_intt_complete as py

    d = os.path.join(HERE, "py_full_ntt_n512")
    os.makedirs(d, exist_ok=True)

    random.seed(20260910)                       # 固定种子保证整包可复现
    n = 512
    q = py.generate_prime(n, bits=30)
    _, omega = py.find_ntt_roots(n, q)
    random.seed(2026 + n)
    data = [random.randrange(q) for _ in range(n)]
    hw = py.HardwareNTTINTT(n, q, omega)

    # 与 reference_ntt_dit / hw.ntt 双重一致性
    ref = py.reference_ntt_dit(data, omega, q)
    assert hw.ntt(data, "logical") == ref, "hw ntt != reference"
    out_phys = hw.ntt(data, "physical")

    # 插桩复刻 ntt() 主体（同一代码路径，仅加日志）
    values = data[:]
    labels = list(range(n))
    stage_files = []
    for s in range(hw.log_n):
        m = 1 << s
        rows = []
        for bi, batch in enumerate(hw.forward_stage_batches(s)):
            regs, mem_pos = hw._load(values, batch)
            regs_log, _ = hw._load(labels, batch)
            for lane in range(64):
                even, odd = 2 * lane, 2 * lane + 1
                a, b = regs[even], regs[odd]
                lower, upper = regs_log[even], regs_log[odd]
                assert upper - lower == m
                w = hw.ntt_twiddle(m, lower)
                t = (b * w) % q
                o0, o1 = (a + t) % q, (a - t) % q
                rows.append([s, m, bi, batch["mode"],
                             batch["first_start"], batch["second_start"],
                             lane, mem_pos[even], mem_pos[odd], lower, upper,
                             a, b, w, t, o0, o1])
                regs[even], regs[odd] = o0, o1
            regs = py.apply_p(regs, count=1)
            regs_log = py.apply_p(regs_log, count=1)
            hw._store(values, regs, mem_pos)
            hw._store(labels, regs_log, mem_pos)
        fn = f"stage{s}_bf_ops.csv"
        wcsv(f"{d}/{fn}",
             ["stage_s", "m", "batch_idx", "load_mode", "first_start", "second_start",
              "lane", "a_mem_pos", "b_mem_pos", "a_logical", "b_logical",
              "pe_a", "pe_b", "twiddle_w", "b*w", "out0(a+b*w)", "out1(a-b*w)"], rows)
        stage_files.append(fn)
        wcsv(f"{d}/stage{s}_mem_after.csv", ["mem_pos", "value", "logical_label"],
             [[i, values[i], labels[i]] for i in range(n)])

    assert values == out_phys, "instrumented final state != hw.ntt physical"

    wcsv(f"{d}/input_poly.csv", ["idx", "value"], [[i, v] for i, v in enumerate(data)])
    wcsv(f"{d}/output_physical.csv", ["mem_pos", "value"],
         [[i, v] for i, v in enumerate(out_phys)])
    wcsv(f"{d}/output_logical.csv", ["coef_idx", "value"],
         [[i, v] for i, v in enumerate(ref)])

    # INTT 旋转因子表（lazy-scale w_bf）+ 往返校验
    intt_sched = hw.precompute_intt_bf_twiddles()
    rows = []
    for st in intt_sched:
        for bi, sb in enumerate(st["batches"]):
            for li, lane in enumerate(sb["lanes"]):
                rows.append([st["stage"], st["forward_stage"], st["m"], bi,
                             li, lane["lower_logical"], lane["upper_logical"],
                             lane["w_forward"], lane["w_dif_inverse"], lane["w_bf"],
                             lane["scale_even_in"], lane["scale_odd_in"]])
    wcsv(f"{d}/intt_bf_twiddles.csv",
         ["stage_k", "fwd_stage_s", "m", "batch_idx", "lane",
          "lower_logical", "upper_logical", "w_forward", "w_dif_inverse",
          "w_bf_actual", "scale_even_in", "scale_odd_in"], rows)
    rt = hw.intt(ref, input_order="logical")
    assert rt == data, "intt round-trip failed"

    with open(f"{d}/params.txt", "w") as f:
        f.write(f"N = {n}\nq = {q} (30-bit prime, generate_prime)\nomega = {omega}\n"
                f"seed_prime = 20260910, seed_data = {2026 + n}\n"
                f"log2(N) = {hw.log_n} stages (s = 0..{hw.log_n - 1})\n"
                f"hw.ntt vs reference_ntt_dit: PASS\n"
                f"instrumented state vs hw.ntt physical: PASS\n"
                f"intt(ntt(data)) round-trip: PASS\n")
    return (f"py_full_ntt_n512: q={q} omega={omega}，{hw.log_n} 级全量 BF 明细"
            f"（每级 1 CSV）+ 级后存储状态 + INTT 旋转因子表 {len(rows)} 行，"
            f"三重校验全 PASS")


def main():
    lines = ["gen_ntt_run_data.py 运行结果（数据源与校验）", "=" * 56]
    for fn in (gen_pntt_slice, gen_pintt_slice, gen_full_pipeline_pintt,
               gen_py_full_ntt):
        lines.append(f"[OK] {fn()}")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
