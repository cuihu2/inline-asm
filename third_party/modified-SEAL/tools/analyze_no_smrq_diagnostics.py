#!/usr/bin/env python3
"""Compare deterministic BFV baseline and no-SMRQ diagnostic logs."""

import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


PREFIX = "NO_SMRQ_CSV,"
INTEGER_FIELDS = {
    "trial",
    "depth",
    "n",
    "k",
    "q_bits",
    "t_bits",
    "t",
    "base_B_size",
    "ciphertext_size",
    "noise_before",
    "noise_after",
    "mismatches",
    "slots",
    "elapsed_us",
}
PAIR_KEY = ("case", "operation", "trial", "depth", "n", "k", "q_bits", "t_bits", "t")


def read_rows(path):
    csv_lines = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            line = line.strip()
            if line.startswith(PREFIX):
                csv_lines.append(line[len(PREFIX) :])

    if not csv_lines:
        raise ValueError(f"{path}: no {PREFIX[:-1]} records found")

    reader = csv.DictReader(csv_lines)
    rows = []
    for row in reader:
        if row.get("mode") == "mode":
            continue
        for field in INTEGER_FIELDS:
            row[field] = int(row[field])
        rows.append(row)
    if not rows:
        raise ValueError(f"{path}: header found but no diagnostic rows found")
    return rows


def paired_key(row):
    return tuple(row[field] for field in PAIR_KEY)


def median(values):
    return statistics.median(values) if values else 0


def guaranteed_depth(rows, noise_margin=None):
    depths_by_trial = defaultdict(list)
    for row in rows:
        depths_by_trial[row["trial"]].append(row)
    successful_depths = []
    for trial_rows in depths_by_trial.values():
        successful_depths.append(
            max(
                (
                    row["depth"]
                    for row in trial_rows
                    if row["mismatches"] == 0
                    and (noise_margin is None or row["noise_after"] >= noise_margin)
                ),
                default=0,
            )
        )
    return min(successful_depths, default=0)


def main():
    parser = argparse.ArgumentParser(
        description="Compare BFV baseline and no-SMRQ diagnostic logs emitted by sealtest"
    )
    parser.add_argument("baseline_log")
    parser.add_argument("nosmrq_log")
    parser.add_argument(
        "--noise-margin",
        type=int,
        default=20,
        help="minimum post-operation noise budget used for the safe-depth columns (default: 20 bits)",
    )
    args = parser.parse_args()

    try:
        baseline_rows = read_rows(args.baseline_log)
        nosmrq_rows = read_rows(args.nosmrq_log)
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2

    baseline = {paired_key(row): row for row in baseline_rows}
    nosmrq = {paired_key(row): row for row in nosmrq_rows}
    common_keys = sorted(set(baseline) & set(nosmrq))
    missing_baseline = sorted(set(nosmrq) - set(baseline))
    missing_nosmrq = sorted(set(baseline) - set(nosmrq))

    if missing_baseline or missing_nosmrq:
        print(
            f"warning: unpaired rows: baseline_missing={len(missing_baseline)}, "
            f"nosmrq_missing={len(missing_nosmrq)}",
            file=sys.stderr,
        )

    groups = defaultdict(list)
    baseline_groups = defaultdict(list)
    nosmrq_groups = defaultdict(list)
    for row in baseline_rows:
        baseline_groups[(row["case"], row["operation"])].append(row)
    for row in nosmrq_rows:
        nosmrq_groups[(row["case"], row["operation"])].append(row)
    for key in common_keys:
        base_row = baseline[key]
        no_row = nosmrq[key]
        groups[(base_row["case"], base_row["operation"])].append((base_row, no_row))

    print(
        "case,operation,rows,baseline_failed_rows,nosmrq_failed_rows,"
        "baseline_min_noise,nosmrq_min_noise,mean_noise_delta,worst_noise_delta,"
        "baseline_correct_depth,nosmrq_correct_depth,baseline_safe_depth,nosmrq_safe_depth,"
        "baseline_median_us,nosmrq_median_us,time_ratio,baseline_B,nosmrq_B"
    )
    for (case_name, operation), pairs in sorted(groups.items()):
        baseline_failed = sum(row["mismatches"] != 0 for row, _ in pairs)
        nosmrq_failed = sum(row["mismatches"] != 0 for _, row in pairs)
        baseline_noise = [row["noise_after"] for row, _ in pairs]
        nosmrq_noise = [row["noise_after"] for _, row in pairs]
        noise_delta = [no_row["noise_after"] - base_row["noise_after"] for base_row, no_row in pairs]
        baseline_time = [row["elapsed_us"] for row, _ in pairs]
        nosmrq_time = [row["elapsed_us"] for _, row in pairs]
        baseline_median = median(baseline_time)
        nosmrq_median = median(nosmrq_time)
        time_ratio = nosmrq_median / baseline_median if baseline_median else 0.0
        baseline_depth = guaranteed_depth(baseline_groups[(case_name, operation)])
        nosmrq_depth = guaranteed_depth(nosmrq_groups[(case_name, operation)])
        baseline_safe_depth = guaranteed_depth(
            baseline_groups[(case_name, operation)], args.noise_margin
        )
        nosmrq_safe_depth = guaranteed_depth(nosmrq_groups[(case_name, operation)], args.noise_margin)

        print(
            f"{case_name},{operation},{len(pairs)},{baseline_failed},{nosmrq_failed},"
            f"{min(baseline_noise)},{min(nosmrq_noise)},{statistics.mean(noise_delta):.2f},"
            f"{min(noise_delta)},{baseline_depth},{nosmrq_depth},{baseline_safe_depth},{nosmrq_safe_depth},"
            f"{baseline_median:.1f},{nosmrq_median:.1f},{time_ratio:.3f},"
            f"{pairs[0][0]['base_B_size']},{pairs[0][1]['base_B_size']}"
        )

    failed_rows = [row for row in nosmrq_rows if row["mismatches"]]
    regression_rows = [
        nosmrq[key]
        for key in common_keys
        if baseline[key]["mismatches"] == 0 and nosmrq[key]["mismatches"] != 0
    ]
    print(
        f"\npaired_rows={len(common_keys)}, nosmrq_failed_rows={len(failed_rows)}, "
        f"nosmrq_regression_rows={len(regression_rows)}, "
        f"baseline_unpaired={len(missing_nosmrq)}, nosmrq_unpaired={len(missing_baseline)}"
    )
    if failed_rows:
        print("first_no_smrq_failures:")
        for row in failed_rows[:10]:
            print(
                f"  case={row['case']} operation={row['operation']} trial={row['trial']} "
                f"depth={row['depth']} noise={row['noise_after']} mismatches={row['mismatches']}/{row['slots']}"
            )

    # A no-SMRQ failure is a regression only when the paired baseline row still decrypts correctly. If no-SMRQ stops
    # a chain earlier, later baseline-only rows are also treated as a regression. Baseline failures shared by no-SMRQ
    # merely identify the common depth limit of that parameter set.
    return 1 if regression_rows or missing_nosmrq else 0


if __name__ == "__main__":
    sys.exit(main())
