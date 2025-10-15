#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
import argparse
import datetime as dt
import os
import re
import sys
from typing import Iterable, Optional, Tuple


# Common timestamp patterns seen in FRR topotest exec.log files.
# We attempt several patterns in order. Each entry is (compiled_regex, strptime_format or None)
# If strptime_format is None, group parsing is used.
TIMESTAMP_PATTERNS: Iterable[Tuple[re.Pattern, Optional[str]]] = [
    # Example: 2025-10-13 14:22:11,123 (Python logging with milliseconds comma)
    (
        re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\b"),
        "%Y-%m-%d %H:%M:%S,%f",
    ),
    # Example: 2025-10-13 14:22:11.123 (milliseconds dot)
    (
        re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6})\b"),
        "%Y-%m-%d %H:%M:%S.%f",
    ),
    # Example: 2025-10-13 14:22:11 (no sub-second)
    (
        re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b"),
        "%Y-%m-%d %H:%M:%S",
    ),
    # Example: 10/13/2025 14:22:11
    (
        re.compile(r"^(?P<ts>\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2})\b"),
        "%m/%d/%Y %H:%M:%S",
    ),
    # Example: 2025-10-13T14:22:11Z or 2025-10-13T14:22:11.123Z
    (
        re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z)\b"),
        "%Y-%m-%dT%H:%M:%S%fZ",
    ),
    # Example: 14:22:11.123 or 14:22:11 (no date) - treated as today
    (re.compile(r"^(?P<ts>\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,6})?)\b"), None),
]


def parse_timestamp(s: str) -> Optional[dt.datetime]:
    s = s.strip()
    for pattern, fmt in TIMESTAMP_PATTERNS:
        m = pattern.search(s)
        if not m:
            continue
        ts = m.group("ts")
        if fmt is None:
            # Time-only case: HH:MM:SS[.uuuuuu]
            # Normalize comma to dot for microseconds
            ts_norm = ts.replace(",", ".")
            try:
                t = dt.datetime.strptime(ts_norm, "%H:%M:%S.%f")
            except ValueError:
                try:
                    t = dt.datetime.strptime(ts_norm, "%H:%M:%S")
                except ValueError:
                    continue
            # Use today's date (local time). This assumes a single-day log.
            today = dt.date.today()
            return dt.datetime.combine(today, t.time())
        else:
            # Some formats include %f optional; allow missing sub-seconds
            try:
                return dt.datetime.strptime(ts, fmt)
            except ValueError:
                # If format had %f but timestamp lacks it, try without
                if "%f" in fmt:
                    try:
                        alt_fmt = fmt.replace(".%f", "").replace("%f", "")
                        return dt.datetime.strptime(ts, alt_fmt)
                    except ValueError:
                        pass
                continue
    return None


def get_first_last_timestamp_from_file(
    path: str,
) -> Tuple[Optional[dt.datetime], Optional[dt.datetime]]:
    first: Optional[dt.datetime] = None
    last: Optional[dt.datetime] = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ts = parse_timestamp(line)
                if ts is None:
                    continue
                if first is None:
                    first = ts
                last = ts
    except OSError as e:
        print(f"ERROR: cannot read {path}: {e}", file=sys.stderr)
    return first, last


def human_duration(delta: dt.timedelta) -> str:
    total_seconds = int(delta.total_seconds())
    microseconds = delta.microseconds
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    if microseconds:
        # Show milliseconds if sub-second
        ms = round(microseconds / 1000)
        return f"{seconds}.{ms:03d}s"
    return f"{seconds}s"


def find_exec_logs(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip typical virtual envs or build dirs
        base = os.path.basename(dirpath)
        if base in {".git", "__pycache__", "node_modules"}:
            continue
        for name in filenames:
            if name == "exec.log":
                yield os.path.join(dirpath, name)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan for exec.log files and report durations"
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=os.getcwd(),
        help="Root directory to scan (default: CWD)",
    )
    parser.add_argument(
        "--relative", action="store_true", help="Print paths relative to root"
    )
    parser.add_argument(
        "--summary", action="store_true", help="Print a summary line at the end"
    )
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    logs = list(find_exec_logs(root))
    if not logs:
        print("No exec.log files found.")
        return 1

    # Build results then sort by duration descending, placing N/A at the end
    results: list[
        tuple[str, Optional[dt.datetime], Optional[dt.datetime], Optional[dt.timedelta]]
    ] = []
    for log_path in logs:
        first, last = get_first_last_timestamp_from_file(log_path)
        duration: Optional[dt.timedelta] = None
        if first and last and last >= first:
            duration = last - first
        display_path = os.path.relpath(log_path, root) if args.relative else log_path
        results.append((display_path, first, last, duration))

    results.sort(
        key=lambda r: (r[3] is None, -(r[3].total_seconds()) if r[3] else 0.0, r[0])
    )

    total = dt.timedelta(0)
    counted = 0
    for display_path, first, last, duration in results:
        if duration is not None:
            total += duration
            counted += 1
            print(
                f"{display_path}\t{human_duration(duration)}\t(start: {first}, end: {last})"
            )
        else:
            print(f"{display_path}\tN/A\t(no parseable timestamps)")

    if args.summary:
        print(
            f"\nFiles: {len(logs)}, With duration: {counted}, Total time: {human_duration(total)}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
