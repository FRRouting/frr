#!/usr/bin/env python3

import argparse
from pathlib import Path

import pandas as pd


def parse_args():
    p = argparse.ArgumentParser(
        description="Merge per-interface OSPF CSVs into a single time-ordered flow."
    )
    p.add_argument(
        "-i",
        "--input",
        required=True,
        nargs="+",
        help="Input CSV file(s) or directory containing CSVs.",
    )
    p.add_argument(
        "--pattern",
        default="*.csv",
        help="Glob pattern for CSV files when an input is a directory (default: *.csv).",
    )
    p.add_argument("-o", "--output", required=True, help="Output CSV file")
    return p.parse_args()


def expand_inputs(inputs, pattern):
    files = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(path.glob(pattern)))
        else:
            files.append(path)
    # de-dup preserving order
    seen = set()
    uniq = []
    for p in files:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq


def _parse_time_column(df, path):
    if "time" not in df.columns:
        raise ValueError(f"Missing 'time' column in {path}")
    t = pd.to_datetime(df["time"], format="%H:%M:%S.%f", errors="coerce")
    if t.isna().all():
        raise ValueError(f"Failed to parse any timestamps in {path}")
    return t


def load_csv_with_time(path):
    df = pd.read_csv(path)
    t = _parse_time_column(df, path)

    if "frame" in df.columns:
        df = df.sort_values(["frame"]).copy()
        t = t.loc[df.index]

    rollover = (t.diff() < pd.Timedelta(0)).cumsum()
    df["_time_dt"] = t + pd.to_timedelta(rollover, unit="D")
    df["_source_name"] = df["label"] if "label" in df.columns else path.name
    return df


def merge_csvs(paths):
    frames = [load_csv_with_time(p) for p in paths]
    if not frames:
        return pd.DataFrame()

    df = pd.concat(frames, ignore_index=True, sort=False)
    sort_cols = ["_time_dt", "_source_name"]
    if "frame" in df.columns:
        sort_cols.append("frame")
    df = df.sort_values(sort_cols).reset_index(drop=True)
    return df


def main():
    args = parse_args()
    csv_files = expand_inputs(args.input, args.pattern)
    if not csv_files:
        raise SystemExit("No CSV files found.")

    merged = merge_csvs(csv_files)
    merged = merged.drop(columns=["_time_dt", "_source_name"], errors="ignore")
    merged.to_csv(args.output, index=False)
    print(f"Wrote merged, time-sorted CSV to {args.output}")


if __name__ == "__main__":
    main()
