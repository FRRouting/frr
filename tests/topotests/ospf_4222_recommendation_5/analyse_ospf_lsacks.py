#!/usr/bin/env python3

import argparse
import pandas as pd


def parse_args():
    p = argparse.ArgumentParser(
        description="Analyze OSPF LSUs vs LSAcks: retransmissions, MaxAge, and ACK latency."
    )
    p.add_argument("-i", "--input", required=True, help="Input CSV file")
    p.add_argument("-o", "--output", required=True, help="Output file (CSV/TXT)")
    return p.parse_args()


def load_csv(filename):
    df = pd.read_csv(filename)
    t = pd.to_datetime(df["time"], format="%H:%M:%S.%f")
    # ensure ordered
    df = df.sort_values(["frame"]).copy()
    # detect midnight rollover: time decreases vs previous row
    rollover = (t.diff() < pd.Timedelta(0)).cumsum()
    df["time_dt"] = t + pd.to_timedelta(rollover, unit="D")
    return df


def extract_lsa_rows(df):
    # LSAs only (non-ACK with an adv_router)
    lsa_df = df[
        (df["adv_router"].notna()) &
        (df["adv_router"] != "") &
        (df["lsa_type_name"].notna()) &
        (df["lsa_type_name"] != "LSA-Ack")
    ].copy()

    # Normalize fields used for keys
    lsa_df["adv_router"] = lsa_df["adv_router"].astype(str).str.strip()
    lsa_df["cksum"] = lsa_df["cksum"].astype(str).str.strip()
    lsa_df["seqnum"] = lsa_df["seqnum"].astype(str).str.strip()

    # age → detect MaxAge LSAs
    lsa_df["age"] = pd.to_numeric(lsa_df["age"], errors="coerce")
    lsa_df["is_maxage"] = lsa_df["age"] == 3600

    # Build internal LSA key (adv_router|lsa_id|seqnum)
    lsa_df["lsa_key"] = (
        lsa_df["adv_router"] + "|" +
        lsa_df["cksum"] + "|" +
        lsa_df["seqnum"]
    )

    return lsa_df


def extract_ack_rows(df):
    # Extract LSA-Acks
    ack_df = df[df["lsa_type_name"] == "LSA-Ack"].copy()
    if ack_df.empty:
        return pd.DataFrame(columns=["lsa_key", "first_ack_time", "last_ack_time", "ack_count", "ack_types"])

    # Expand the semicolon-separated list into one row per acked LSA
    ack_df["tuple_list"] = ack_df["lsa_id"].astype(str).str.split(";")
    ack_exp = ack_df.explode("tuple_list").copy()
    ack_exp = ack_exp[ack_exp["tuple_list"].notna() & (ack_exp["tuple_list"].astype(str).str.strip() != "")]

    # Parse "adv|lsid|seq|type" (4th field is not reliable for matching, but useful diagnostically)
    parts = ack_exp["tuple_list"].astype(str).str.split("|", expand=True, regex=False)
    parts = parts.iloc[:, :4]
    parts.columns = ["adv_ack", "cksum_ack", "seq_ack", "type_ack"]
    ack_exp = pd.concat([ack_exp, parts], axis=1)

    # Normalize
    for c in ["adv_ack", "cksum_ack", "seq_ack", "type_ack"]:
        ack_exp[c] = ack_exp[c].astype(str).str.strip()

    # Build ACK match key WITHOUT type
    ack_exp["lsa_key"] = (
        ack_exp["adv_ack"] + "|" +
        ack_exp["cksum_ack"] + "|" +
        ack_exp["seq_ack"]
    )

    # Aggregate ACK info per LSA key
    ack_agg = (
        ack_exp.groupby("lsa_key")
        .agg(
            first_ack_time=("time_dt", "min"),
            last_ack_time=("time_dt", "max"),
            ack_count=("time_dt", "count"),
            ack_types=("type_ack", lambda s: ",".join(sorted(set(s)))),
        )
        .reset_index()
    )

    return ack_agg

def summarize(lsa_df, ack_agg):
    if lsa_df.empty:
        return pd.DataFrame(columns=[
            "adv_router", "cksum", "seqnum", "lsa_type_name", "lsa_id",
            "first_tx_time",
            "normal_tx_count", "maxage_tx_count",
            "has_maxage", "maxage_only",
            "ack_count",
            "first_ack_time", "last_ack_time",
            "first_ack_latency_s", "last_ack_latency_s",
            "first_maxage_tx_time", "acks_after_maxage",
        ])

    grouped = lsa_df.groupby(["lsa_key", "adv_router", "cksum", "seqnum", "lsa_type_name", "lsa_id"])

    summary = grouped.agg(
        first_tx_time=("time_dt", "min"),
        normal_tx_count=("is_maxage", lambda s: (~s).sum()),
        maxage_tx_count=("is_maxage", "sum"),
        has_maxage=("is_maxage", "max"),
        all_maxage=("is_maxage", "min"),
    ).reset_index()

    summary["maxage_only"] = summary["all_maxage"]
    summary = summary.drop(columns=["all_maxage"])

    # --- NEW: first MaxAge TX time per lsa_key (NaT if never MaxAge) ---
    first_maxage = (
        lsa_df[lsa_df["is_maxage"]]
        .groupby("lsa_key")["time_dt"]
        .min()
        .rename("first_maxage_tx_time")
        .reset_index()
    )
    summary = summary.merge(first_maxage, how="left", on="lsa_key")

    # Merge ACK data (ack_agg must be grouped by lsa_key)
    summary = summary.merge(ack_agg, how="left", on="lsa_key")
    summary["ack_count"] = summary["ack_count"].fillna(0).astype(int)

    # --- NEW: latency only for ACKs that are "for the first (normal) lifecycle" ---
    valid_ack = summary["first_ack_time"].notna()

    # If we saw a MaxAge TX, only accept ACKs that happened before that MaxAge TX
    has_maxage_time = summary["first_maxage_tx_time"].notna()
    valid_ack &= (~has_maxage_time) | (summary["first_ack_time"] < summary["first_maxage_tx_time"])

    # Also require ACK after first TX time
    valid_ack &= summary["first_ack_time"] >= summary["first_tx_time"]

    summary["first_ack_latency_s"] = float("nan")
    summary.loc[valid_ack, "first_ack_latency_s"] = (
        (summary.loc[valid_ack, "first_ack_time"] - summary.loc[valid_ack, "first_tx_time"])
        .dt.total_seconds()
    )

    # In this model, "last latency" should NOT span into MaxAge lifecycle.
    # So just mirror first_ack_latency_s (or leave NaN if invalid).
    summary["last_ack_latency_s"] = summary["first_ack_latency_s"]

    # Diagnostic: did we see any ACK after MaxAge?
    summary["acks_after_maxage"] = (
        summary["last_ack_time"].notna() &
        summary["first_maxage_tx_time"].notna() &
        (summary["last_ack_time"] > summary["first_maxage_tx_time"])
    )

    # Remove internal key
    summary = summary.drop(columns=["lsa_key"])
    summary = summary.drop(columns=["has_maxage"])
    summary = summary.drop(columns=["acks_after_maxage"])

    col_order = [
        "adv_router", "cksum", "seqnum", "lsa_type_name", "lsa_id",
        "first_tx_time",
        "normal_tx_count", "maxage_tx_count",
        "maxage_only",
        "ack_count",
        "first_ack_time", "last_ack_time",
        "first_ack_latency_s", "last_ack_latency_s",
        "first_maxage_tx_time",
    ]

    return summary.sort_values(by="first_tx_time")[col_order]


def format_for_output(summary):
    summary = summary.copy()

    # Compact timestamps (HH:MM:SS.mmm)
    time_cols = ["first_tx_time", "first_ack_time", "last_ack_time", "first_maxage_tx_time"]
    for col in time_cols:
        if col in summary.columns:
            summary[col] = pd.to_datetime(summary[col], errors="coerce")
            summary[col] = summary[col].dt.strftime("%H:%M:%S.%f").str[:12]
            summary[col] = summary[col].fillna("")  # NaT -> ""

    # Round latencies
    for col in ["first_ack_latency_s", "last_ack_latency_s"]:
        if col in summary.columns:
            summary[col] = pd.to_numeric(summary[col], errors="coerce").round(6)

    # Clean booleans
    for col in ["maxage_only"]:
    #for col in ["has_maxage", "maxage_only", "acks_after_maxage"]:
        if col in summary.columns:
            summary[col] = summary[col].fillna(False).astype(bool)

    return summary


def main():
    args = parse_args()

    df = load_csv(args.input)
    lsa_df = extract_lsa_rows(df)
    ack_agg = extract_ack_rows(df)

    summary = summarize(lsa_df, ack_agg)
    summary = format_for_output(summary)

    if args.output.lower().endswith(".csv"):
        summary.to_csv(args.output, index=False)
        print(f"Wrote CSV summary to {args.output}")
    else:
        pd.set_option("display.width", 140)
        pd.set_option("display.max_colwidth", 40)
        with open(args.output, "w") as f:
            f.write(summary.to_string(index=False))
        print(f"Wrote text summary to {args.output}")


if __name__ == "__main__":
    main()


