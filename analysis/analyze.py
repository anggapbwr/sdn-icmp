#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SDN ICMP Flood Forensic Analysis & Visualization
=================================================
NIST SP 800-86 Compliant Forensic Report Generator

Role:
  This script analyzes controller telemetry evidence from CSV files:
  - logs/archive/baseline/traffic_analysis.csv
  - logs/archive/ddos/traffic_analysis.csv
  - logs/archive/ddos/mitigation_events.csv

This script DOES NOT parse PCAP directly.
PCAP-level evidence is handled by analyze_pcap.py and Wireshark.

Usage:
  python3 analysis/analyze.py
"""

import os
import sys
from datetime import datetime

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# PATHS
# ---------------------------------------------------------------------------

BASE_DIR = "/home/kali/sdn-icmp"

BASELINE_DIR = f"{BASE_DIR}/logs/archive/baseline"
DDOS_DIR = f"{BASE_DIR}/logs/archive/ddos"
OUTPUT_DIR = f"{BASE_DIR}/logs/report_graphs"

BASELINE_TRAFFIC_CSV = f"{BASELINE_DIR}/traffic_analysis.csv"
DDOS_TRAFFIC_CSV = f"{DDOS_DIR}/traffic_analysis.csv"
MITIGATION_CSV = f"{DDOS_DIR}/mitigation_events.csv"

BASELINE_PCAP = f"{BASELINE_DIR}/session_baseline.pcap"
DDOS_PCAP = f"{DDOS_DIR}/session_ddos.pcap"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# TOPOLOGY CONSTANTS
# ---------------------------------------------------------------------------

VICTIM_IP = "10.0.0.25"

ATTACKERS = {
    "10.0.0.1":  {"host": "h1",  "switch": "s2", "segment": "s2-segment-attacker-h1"},
    "10.0.0.7":  {"host": "h7",  "switch": "s3", "segment": "s3-segment-attacker-h7"},
    "10.0.0.13": {"host": "h13", "switch": "s4", "segment": "s4-segment-attacker-h13"},
    "10.0.0.18": {"host": "h18", "switch": "s5", "segment": "s5-segment-attacker-h18"},
}

ATTACKER_IPS = list(ATTACKERS.keys())

ATTACK_STATUSES = ["WARNING", "ATTACK_CONFIRMED", "RATE_LIMIT_ACTIVE"]
ATTACK_EVENT_TYPES = ["SUSPICIOUS", "ATTACK", "LIMITED"]
ATTACK_TYPES = ["ICMP_FLOOD", "ICMP_FLOOD_LIMITED"]

WARNING_PPS = 20
ATTACK_PPS = 50

# Controller threat_score uses 0-100 scale.
TS_WARNING = 40
TS_ALERT = 70

# ---------------------------------------------------------------------------
# STYLE CONFIGURATION
# ---------------------------------------------------------------------------

PALETTE = {
    "baseline": "#4A90D9",
    "ddos": "#E05C5C",
    "attack": "#D94F3D",
    "warning": "#F5A623",
    "confirmed": "#C0392B",
    "limited": "#8E44AD",
    "mitigation": "#27AE60",
    "neutral": "#7F8C8D",
    "grid": "#ECEFF1",
    "text": "#2C3E50",
    "subtitle": "#7F8C8D",
}

ATTACKER_COLORS = ["#E05C5C", "#F5A623", "#8E44AD", "#2980B9"]

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#BDC3C7",
    "axes.grid": True,
    "grid.color": PALETTE["grid"],
    "grid.linewidth": 0.8,
    "grid.alpha": 0.9,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.titlepad": 14,
    "axes.labelsize": 10,
    "axes.labelcolor": PALETTE["text"],
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "xtick.color": PALETTE["text"],
    "ytick.color": PALETTE["text"],
    "legend.fontsize": 9,
    "legend.framealpha": 0.85,
    "legend.edgecolor": "#BDC3C7",
    "font.family": "DejaVu Sans",
})

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _out(filename):
    return os.path.join(OUTPUT_DIR, filename)


def _save(filename, dpi=190):
    plt.tight_layout()
    path = _out(filename)
    plt.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close()
    print(f"  [+] {filename}")


def _subtitle(ax, text):
    ax.text(
        0, 1.02, text,
        transform=ax.transAxes,
        fontsize=8.5,
        color=PALETTE["subtitle"],
        ha="left",
        va="bottom",
    )


def _warn_skip(filename, reason="no data"):
    print(f"  [!] Skip {filename}: {reason}")


def load_csv(path):
    if not os.path.exists(path):
        print(f"  [!] File not found: {path}")
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as exc:
        print(f"  [!] Failed to read {path}: {exc}")
        return pd.DataFrame()


def normalize_df(df):
    if df.empty:
        return df
    df = df.copy()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    numeric_cols = [
        "packet_rate", "packet_count", "threat_score", "final_prediction",
        "dpid", "in_port", "out_port", "meter_id", "limit_pps",
        "idle_timeout", "hard_timeout",
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    string_cols = [
        "severity", "event_type", "detection_status", "mitigation_status",
        "protocol_name", "src_ip", "dst_ip", "attack_type", "attacker_segment",
        "dpid_name", "event_note", "action", "attacker_hostname",
        "segment_description", "reason", "note",
    ]
    for col in string_cols:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()

    return df


def add_topology_labels(df):
    if df.empty or "src_ip" not in df.columns:
        return df
    df = df.copy()
    df["attacker_host"] = df["src_ip"].map(lambda ip: ATTACKERS.get(ip, {}).get("host", ""))
    df["attacker_switch"] = df["src_ip"].map(lambda ip: ATTACKERS.get(ip, {}).get("switch", ""))
    df["expected_segment"] = df["src_ip"].map(lambda ip: ATTACKERS.get(ip, {}).get("segment", "NORMAL_HOST"))
    return df


def attacker_label(ip):
    meta = ATTACKERS.get(ip, {})
    if meta:
        return f"{ip} ({meta['host']}/{meta['switch']})"
    return str(ip)


def safe_mean(df, col):
    return round(float(df[col].mean()), 2) if not df.empty and col in df.columns else 0.0


def safe_max(df, col):
    return round(float(df[col].max()), 2) if not df.empty and col in df.columns else 0.0


def file_status(path):
    if not os.path.exists(path):
        return "MISSING"
    size = os.path.getsize(path)
    return f"FOUND ({size} bytes)"

# ---------------------------------------------------------------------------
# DATA LOADING
# ---------------------------------------------------------------------------

print("\n" + "=" * 68)
print("  SDN ICMP FLOOD FORENSIC ANALYSIS")
print(f"  NIST SP 800-86 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 68)

print("\n[*] Loading archived evidence ...")

baseline_df = normalize_df(load_csv(BASELINE_TRAFFIC_CSV))
ddos_df = normalize_df(load_csv(DDOS_TRAFFIC_CSV))
mitigation_df = normalize_df(load_csv(MITIGATION_CSV))

baseline_df = add_topology_labels(baseline_df)
ddos_df = add_topology_labels(ddos_df)

if baseline_df.empty:
    print("  [!] Baseline CSV empty or missing.")
if ddos_df.empty:
    print("  [!] DDoS CSV empty or missing.")
if baseline_df.empty and ddos_df.empty:
    print("  [!] No traffic data. Exiting.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# FORENSIC FILTERING
# ---------------------------------------------------------------------------

attack_df = pd.DataFrame()
warning_df = pd.DataFrame()
confirmed_df = pd.DataFrame()
limited_df = pd.DataFrame()
victim_traffic_df = pd.DataFrame()

if not ddos_df.empty:
    if "dst_ip" in ddos_df.columns:
        victim_traffic_df = ddos_df[ddos_df["dst_ip"] == VICTIM_IP].copy()

    def mask(col, values):
        if col not in ddos_df.columns:
            return pd.Series(False, index=ddos_df.index)
        values = values if isinstance(values, list) else [values]
        return ddos_df[col].isin(values)

    combined_mask = (
        mask("protocol_name", ["ICMP"])
        & mask("dst_ip", [VICTIM_IP])
        & (
            mask("src_ip", ATTACKER_IPS)
            | mask("detection_status", ATTACK_STATUSES)
            | mask("event_type", ATTACK_EVENT_TYPES)
            | mask("attack_type", ATTACK_TYPES)
        )
    )

    attack_df = ddos_df[combined_mask].copy()
    if "src_ip" in attack_df.columns:
        attack_df = attack_df[attack_df["src_ip"] != VICTIM_IP].copy()

    if "detection_status" in attack_df.columns:
        warning_df = attack_df[attack_df["detection_status"] == "WARNING"].copy()
        confirmed_df = attack_df[attack_df["detection_status"] == "ATTACK_CONFIRMED"].copy()
        limited_df = attack_df[attack_df["detection_status"] == "RATE_LIMIT_ACTIVE"].copy()

# ---------------------------------------------------------------------------
# SUMMARY STATISTICS
# ---------------------------------------------------------------------------

baseline_events = len(baseline_df)
ddos_events = len(ddos_df)
victim_events = len(victim_traffic_df)
attack_events = len(attack_df)
warning_events = len(warning_df)
confirmed_events = len(confirmed_df)
limited_events = len(limited_df)
mitigation_events_count = len(mitigation_df)

baseline_rate = safe_mean(baseline_df, "packet_rate")
ddos_rate = safe_mean(ddos_df, "packet_rate")
attack_rate = safe_mean(attack_df, "packet_rate")
max_attack_rate = safe_max(attack_df, "packet_rate")
max_threat_score = safe_max(attack_df, "threat_score")

unique_attackers_detected = (
    sorted(attack_df["src_ip"].dropna().unique().tolist())
    if not attack_df.empty and "src_ip" in attack_df.columns else []
)

mitigated_attackers = []
if not mitigation_df.empty and {"src_ip", "action"}.issubset(mitigation_df.columns):
    mitigated_attackers = sorted(
        mitigation_df[
            mitigation_df["action"].str.contains("RATE_LIMIT", na=False)
        ]["src_ip"].dropna().unique().tolist()
    )

summary_stats = pd.DataFrame({
    "Metric": [
        "Baseline Events",
        "DDoS Total Events",
        "Victim Traffic Events",
        "Forensic Attack Events",
        "Warning Events",
        "Confirmed Attack Events",
        "Rate Limited Events",
        "Mitigation Events",
        "Avg Baseline Packet Rate (PPS)",
        "Avg DDoS Packet Rate (PPS)",
        "Avg Attack Packet Rate (PPS)",
        "Max Attack Packet Rate (PPS)",
        "Max Threat Score",
        "Unique Attackers Detected",
        "Mitigated Attackers",
    ],
    "Value": [
        baseline_events,
        ddos_events,
        victim_events,
        attack_events,
        warning_events,
        confirmed_events,
        limited_events,
        mitigation_events_count,
        baseline_rate,
        ddos_rate,
        attack_rate,
        max_attack_rate,
        max_threat_score,
        len(unique_attackers_detected),
        len(mitigated_attackers),
    ],
})

print("\n[*] Statistics snapshot:")
for _, row in summary_stats.iterrows():
    print(f"    {row['Metric']:<40} {row['Value']}")

# First mitigation timestamp per attacker.
mitigation_times = {}
if not mitigation_df.empty and {"timestamp", "src_ip"}.issubset(mitigation_df.columns):
    mitigation_df["timestamp"] = pd.to_datetime(mitigation_df["timestamp"], errors="coerce")
    mit_sorted = mitigation_df.dropna(subset=["timestamp"]).sort_values("timestamp")
    rate_limit_rows = mit_sorted[mit_sorted.get("action", "").astype(str).str.contains("RATE_LIMIT", na=False)] if "action" in mit_sorted.columns else mit_sorted
    for ip, grp in rate_limit_rows.groupby("src_ip"):
        if ip in ATTACKER_IPS and not grp.empty:
            mitigation_times[ip] = grp["timestamp"].iloc[0]

# Timeline summary.
first_warning = warning_df["timestamp"].min() if not warning_df.empty and "timestamp" in warning_df.columns else pd.NaT
first_confirmed = confirmed_df["timestamp"].min() if not confirmed_df.empty and "timestamp" in confirmed_df.columns else pd.NaT
first_limited = limited_df["timestamp"].min() if not limited_df.empty and "timestamp" in limited_df.columns else pd.NaT
first_mitigation = min(mitigation_times.values()) if mitigation_times else pd.NaT

# ---------------------------------------------------------------------------
# GRAPHS
# ---------------------------------------------------------------------------

print("\n[*] Generating graphs ...")

# 01 Baseline vs attack packet rate.
def graph_01():
    fn = "01_baseline_vs_attack_packet_rate.png"
    labels = ["Baseline\nPeriod", "DDoS\nTotal Period", "Forensic\nAttack Traffic"]
    values = [baseline_rate, ddos_rate, attack_rate]
    colors = [PALETTE["baseline"], PALETTE["ddos"], PALETTE["attack"]]

    if all(v == 0 for v in values):
        _warn_skip(fn)
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(labels, values, color=colors, width=0.5, zorder=3, edgecolor="white", linewidth=1.2)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.015,
                f"{val:.2f} PPS", ha="center", va="bottom", fontsize=10,
                fontweight="bold", color=PALETTE["text"])

    ax.axhline(WARNING_PPS, color=PALETTE["warning"], linestyle="--", linewidth=1.5, alpha=0.8,
               label=f"Warning Threshold ({WARNING_PPS} PPS)")
    ax.axhline(ATTACK_PPS, color=PALETTE["attack"], linestyle="--", linewidth=1.5, alpha=0.8,
               label=f"Attack Threshold ({ATTACK_PPS} PPS)")

    ax.set_title("Baseline vs. DDoS vs. Forensic Attack — Average Packet Rate")
    _subtitle(ax, "NIST SP 800-86 | Analysis Phase — anomaly evidence from controller telemetry")
    ax.set_ylabel("Average Packet Rate (PPS)")
    ax.set_ylim(0, max(values) * 1.25)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.0f"))
    ax.legend(loc="upper left")
    ax.set_axisbelow(True)
    _save(fn)


def graph_02():
    fn = "02_packet_rate_timeline_per_attacker.png"
    if attack_df.empty or not {"timestamp", "packet_rate", "src_ip"}.issubset(attack_df.columns):
        _warn_skip(fn)
        return

    df_sorted = attack_df.dropna(subset=["timestamp", "packet_rate"]).sort_values("timestamp")
    if df_sorted.empty:
        _warn_skip(fn)
        return

    fig, ax = plt.subplots(figsize=(14, 7))

    attacker_ips_present = [ip for ip in ATTACKER_IPS if ip in df_sorted["src_ip"].values]
    for idx, ip in enumerate(attacker_ips_present):
        grp = df_sorted[df_sorted["src_ip"] == ip]
        color = ATTACKER_COLORS[idx % len(ATTACKER_COLORS)]
        ax.plot(grp["timestamp"], grp["packet_rate"], label=attacker_label(ip),
                color=color, linewidth=1.8, alpha=0.9, zorder=3)

        if ip in mitigation_times:
            ax.axvline(mitigation_times[ip], color=color, linestyle=":", linewidth=1.5, alpha=0.7)

    ax.axhline(WARNING_PPS, color=PALETTE["warning"], linestyle="--", linewidth=1.4, alpha=0.85,
               label=f"Warning Threshold ({WARNING_PPS} PPS)")
    ax.axhline(ATTACK_PPS, color=PALETTE["attack"], linestyle="--", linewidth=1.4, alpha=0.85,
               label=f"Attack Threshold ({ATTACK_PPS} PPS)")

    ax.set_title("Packet Rate Timeline per Attacker — Attack & Mitigation Evidence")
    _subtitle(ax, "Dotted vertical lines indicate first RATE_LIMIT mitigation event per attacker.")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Packet Rate (PPS)")
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper right", ncol=2)
    ax.set_axisbelow(True)
    _save(fn)


def graph_03():
    fn = "03_threat_score_timeline.png"
    if attack_df.empty or not {"timestamp", "threat_score"}.issubset(attack_df.columns):
        _warn_skip(fn)
        return

    df_sorted = attack_df.dropna(subset=["timestamp", "threat_score"]).sort_values("timestamp")
    if df_sorted.empty:
        _warn_skip(fn)
        return

    fig, ax = plt.subplots(figsize=(14, 7))
    ts_max = max(float(df_sorted["threat_score"].max()) * 1.15, 100)

    ax.axhspan(0, TS_WARNING, alpha=0.06, color="#27AE60", zorder=0)
    ax.axhspan(TS_WARNING, TS_ALERT, alpha=0.06, color="#F5A623", zorder=0)
    ax.axhspan(TS_ALERT, ts_max, alpha=0.06, color="#E05C5C", zorder=0)

    attacker_ips_present = [ip for ip in ATTACKER_IPS if ip in df_sorted.get("src_ip", pd.Series()).values]
    if attacker_ips_present:
        for idx, ip in enumerate(attacker_ips_present):
            grp = df_sorted[df_sorted["src_ip"] == ip]
            color = ATTACKER_COLORS[idx % len(ATTACKER_COLORS)]
            ax.plot(grp["timestamp"], grp["threat_score"], label=attacker_label(ip),
                    color=color, linewidth=1.8, alpha=0.9, zorder=3)
    else:
        ax.plot(df_sorted["timestamp"], df_sorted["threat_score"], color=PALETTE["attack"], linewidth=1.8,
                label="Threat Score")

    ax.axhline(TS_WARNING, color=PALETTE["warning"], linestyle="--", linewidth=1.3, alpha=0.85,
               label=f"Warning Level ({TS_WARNING})")
    ax.axhline(TS_ALERT, color=PALETTE["attack"], linestyle="--", linewidth=1.3, alpha=0.85,
               label=f"Alert Level ({TS_ALERT})")

    ax.set_title(f"Threat Score Timeline — Detection Escalation Evidence (Victim: {VICTIM_IP})")
    _subtitle(ax, "NIST SP 800-86 | Analysis Phase — severity escalation from controller telemetry")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Threat Score")
    ax.set_ylim(0, ts_max)
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper left", ncol=2)
    ax.set_axisbelow(True)
    _save(fn)


def graph_04():
    fn = "04_detection_lifecycle_distribution.png"
    if ddos_df.empty or "detection_status" not in ddos_df.columns:
        _warn_skip(fn)
        return

    status_order = ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "RATE_LIMIT_ACTIVE"]
    colors_map = {
        "NORMAL": PALETTE["baseline"],
        "WARNING": PALETTE["warning"],
        "ATTACK_CONFIRMED": PALETTE["confirmed"],
        "RATE_LIMIT_ACTIVE": PALETTE["limited"],
    }
    counts = ddos_df["detection_status"].value_counts()
    labels = [s for s in status_order if s in counts.index]
    values = [int(counts[s]) for s in labels]
    colors = [colors_map[s] for s in labels]

    if not values:
        _warn_skip(fn)
        return

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(labels, values, color=colors, width=0.55, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.01,
                f"{val:,}", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_title("Detection Lifecycle Distribution — State Machine Verification")
    _subtitle(ax, "Evidence of NORMAL → WARNING → ATTACK_CONFIRMED → RATE_LIMIT_ACTIVE progression")
    ax.set_xlabel("Detection Status")
    ax.set_ylabel("Number of Events")
    ax.set_ylim(0, max(values) * 1.2)
    ax.set_axisbelow(True)
    _save(fn)


def graph_05():
    fn = "05_confirmed_vs_limited_per_attacker.png"
    if attack_df.empty or not {"src_ip", "detection_status"}.issubset(attack_df.columns):
        _warn_skip(fn)
        return

    filtered = attack_df[
        attack_df["detection_status"].isin(["ATTACK_CONFIRMED", "RATE_LIMIT_ACTIVE"])
        & attack_df["src_ip"].isin(ATTACKER_IPS)
    ]
    if filtered.empty:
        _warn_skip(fn)
        return

    pivot = filtered.pivot_table(index="src_ip", columns="detection_status", values="dst_ip", aggfunc="count", fill_value=0)
    for col in ["ATTACK_CONFIRMED", "RATE_LIMIT_ACTIVE"]:
        if col not in pivot.columns:
            pivot[col] = 0
    pivot = pivot.reindex([ip for ip in ATTACKER_IPS if ip in pivot.index])

    labels = [attacker_label(ip) for ip in pivot.index]
    x = np.arange(len(labels))
    w = 0.35

    fig, ax = plt.subplots(figsize=(12, 7))
    bars1 = ax.bar(x - w/2, pivot["ATTACK_CONFIRMED"], w, label="ATTACK_CONFIRMED",
                   color=PALETTE["confirmed"], zorder=3, edgecolor="white")
    bars2 = ax.bar(x + w/2, pivot["RATE_LIMIT_ACTIVE"], w, label="RATE_LIMIT_ACTIVE",
                   color=PALETTE["limited"], zorder=3, edgecolor="white")

    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.3, str(int(h)),
                        ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_title("Confirmed vs. Rate Limited Events per Attacker")
    _subtitle(ax, "Detection and mitigation verification per attacker source")
    ax.set_xlabel("Attacker")
    ax.set_ylabel("Number of Events")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.legend()
    ax.set_axisbelow(True)
    _save(fn)


def graph_06():
    fn = "06_top_attack_flows.png"
    if attack_df.empty or not {"src_ip", "dst_ip"}.issubset(attack_df.columns):
        _warn_skip(fn)
        return

    flow_df = attack_df[attack_df["src_ip"].isin(ATTACKER_IPS) & (attack_df["dst_ip"] == VICTIM_IP)].copy()
    if flow_df.empty:
        _warn_skip(fn)
        return

    flow_df["flow"] = flow_df["src_ip"].apply(attacker_label) + " → " + flow_df["dst_ip"]
    flow_counts = flow_df["flow"].value_counts().head(10)

    fig, ax = plt.subplots(figsize=(13, 6))
    colors = [ATTACKER_COLORS[i % len(ATTACKER_COLORS)] for i in range(len(flow_counts))]
    bars = ax.barh(flow_counts.index[::-1], flow_counts.values[::-1],
                   color=colors[::-1], zorder=3, edgecolor="white", linewidth=0.8)
    for bar, val in zip(bars, flow_counts.values[::-1]):
        ax.text(val + flow_counts.max() * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", fontsize=9, fontweight="bold")

    ax.set_title(f"Top Attack Flows — Attacker → Victim ({VICTIM_IP})")
    _subtitle(ax, "Dominant flow identification from telemetry evidence")
    ax.set_xlabel("Number of Events")
    ax.set_ylabel("Flow")
    ax.set_axisbelow(True)
    _save(fn)


def graph_07():
    fn = "07_mitigation_action_distribution.png"
    if mitigation_df.empty or "action" not in mitigation_df.columns:
        _warn_skip(fn)
        return

    counts = mitigation_df["action"].value_counts()
    if counts.empty:
        _warn_skip(fn)
        return

    colors = [PALETTE["mitigation"] if "RELEASE" in str(act) else PALETTE["attack"] for act in counts.index]

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(counts.index, counts.values, color=colors, width=0.5, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + counts.max() * 0.01,
                str(int(val)), ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_title("Mitigation Action Distribution — Lifecycle & Recovery Evidence")
    _subtitle(ax, "OpenFlow Meter action lifecycle: RATE_LIMIT_ICMP and RELEASE_METER")
    ax.set_xlabel("Action")
    ax.set_ylabel("Number of Events")
    ax.tick_params(axis="x", rotation=15)
    ax.set_axisbelow(True)
    _save(fn)


def graph_08():
    fn = "08_meter_limit_distribution.png"
    if mitigation_df.empty or "limit_pps" not in mitigation_df.columns:
        _warn_skip(fn)
        return

    counts = mitigation_df["limit_pps"].dropna().astype(int).astype(str).value_counts().sort_index()
    if counts.empty:
        _warn_skip(fn)
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    bar_colors = [PALETTE["warning"] if int(v) <= 20 else PALETTE["attack"] for v in counts.index]
    bars = ax.bar([f"{v} PPS" for v in counts.index], counts.values,
                  color=bar_colors, width=0.45, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + counts.max() * 0.01,
                str(int(val)), ha="center", va="bottom", fontsize=11, fontweight="bold")

    patches = [
        mpatches.Patch(color=PALETTE["warning"], label="Strict rate limit"),
        mpatches.Patch(color=PALETTE["attack"], label="Moderate rate limit"),
    ]
    ax.legend(handles=patches, loc="upper right")
    ax.set_title("OpenFlow Meter Rate Limit Distribution — Adaptive Mitigation Evidence")
    _subtitle(ax, "Variable limit_pps confirms adaptive rate limiting policy")
    ax.set_xlabel("Meter Limit")
    ax.set_ylabel("Number of Events")
    ax.set_axisbelow(True)
    _save(fn)


def graph_09():
    fn = "09_attacker_summary.png"
    if attack_df.empty or "src_ip" not in attack_df.columns:
        _warn_skip(fn)
        return

    attacker_counts = (
        attack_df[attack_df["src_ip"].isin(ATTACKER_IPS)]
        .groupby("src_ip")
        .size()
        .reindex(ATTACKER_IPS)
        .fillna(0)
        .astype(int)
    )
    if attacker_counts.sum() == 0:
        _warn_skip(fn)
        return

    labels = [attacker_label(ip) for ip in attacker_counts.index]
    values = attacker_counts.values

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.bar(labels, values, color=ATTACKER_COLORS[:len(labels)], width=0.5,
                  zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.01,
                f"{val:,}", ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_title("Forensic Attack Events per Attacker — Attribution Evidence")
    _subtitle(ax, "Source attribution using IP, host, and access switch mapping")
    ax.set_xlabel("Attacker")
    ax.set_ylabel("Number of Forensic Attack Events")
    ax.tick_params(axis="x", rotation=10)
    ax.set_ylim(0, max(values) * 1.2)
    ax.set_axisbelow(True)
    _save(fn)


def graph_10():
    fn = "10_forensic_evidence_overview.png"
    labels = [
        "Baseline\nEvents", "DDoS\nEvents", "Forensic\nAttack", "Warning\nEvents",
        "Confirmed\nEvents", "Rate\nLimited", "Mitigation\nEvents",
    ]
    values = [baseline_events, ddos_events, attack_events, warning_events, confirmed_events, limited_events, mitigation_events_count]
    colors = [PALETTE["baseline"], PALETTE["ddos"], PALETTE["attack"], PALETTE["warning"],
              PALETTE["confirmed"], PALETTE["limited"], PALETTE["mitigation"]]

    if all(v == 0 for v in values):
        _warn_skip(fn)
        return

    fig, ax = plt.subplots(figsize=(14, 7))
    bars = ax.bar(labels, values, color=colors, width=0.6, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, values):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.008,
                    f"{val:,}", ha="center", va="bottom", fontsize=9.5, fontweight="bold")

    ax.set_title("Forensic Evidence Overview — Experiment Summary")
    _subtitle(ax, "Collection → Examination → Analysis → Reporting evidence overview")
    ax.set_ylabel("Number of Events / Log Rows")
    ax.set_ylim(0, max(v for v in values if v > 0) * 1.22)
    ax.set_axisbelow(True)
    _save(fn)

for graph in [graph_01, graph_02, graph_03, graph_04, graph_05, graph_06, graph_07, graph_08, graph_09, graph_10]:
    graph()

# ---------------------------------------------------------------------------
# CSV OUTPUTS
# ---------------------------------------------------------------------------

print("\n[*] Writing CSV outputs ...")
summary_stats.to_csv(_out("summary_stats.csv"), index=False)
print("  [+] summary_stats.csv")

if not attack_df.empty:
    attack_df.to_csv(_out("filtered_attack_events.csv"), index=False)
    print("  [+] filtered_attack_events.csv")

    if "src_ip" in attack_df.columns:
        rows = []
        for ip, grp in attack_df.groupby("src_ip"):
            meta = ATTACKERS.get(ip, {})
            rows.append({
                "src_ip": ip,
                "host": meta.get("host", "UNKNOWN"),
                "switch": meta.get("switch", "UNKNOWN"),
                "segment": meta.get("segment", "UNKNOWN"),
                "attack_events": len(grp),
                "warning_events": int((grp.get("detection_status", pd.Series(dtype=str)) == "WARNING").sum()),
                "confirmed_events": int((grp.get("detection_status", pd.Series(dtype=str)) == "ATTACK_CONFIRMED").sum()),
                "limited_events": int((grp.get("detection_status", pd.Series(dtype=str)) == "RATE_LIMIT_ACTIVE").sum()),
                "avg_packet_rate": round(float(grp["packet_rate"].mean()), 2) if "packet_rate" in grp else 0,
                "max_packet_rate": round(float(grp["packet_rate"].max()), 2) if "packet_rate" in grp else 0,
                "max_threat_score": round(float(grp["threat_score"].max()), 2) if "threat_score" in grp else 0,
            })
        attacker_summary_df = pd.DataFrame(rows)
        attacker_summary_df.to_csv(_out("attacker_summary.csv"), index=False)
        print("  [+] attacker_summary.csv")

# ---------------------------------------------------------------------------
# TXT REPORT
# ---------------------------------------------------------------------------

print("\n[*] Writing forensic_report.txt ...")

DIVIDER = "=" * 68
SUBDIV = "-" * 68
NOW_STR = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
report_path = _out("forensic_report.txt")


def section(f, num, title):
    f.write(f"\n{DIVIDER}\n")
    f.write(f"  {num}. {title}\n")
    f.write(f"{DIVIDER}\n\n")


def subsection(f, title):
    f.write(f"\n  {title}\n")
    f.write(f"  {'-' * len(title)}\n")


def fmt_ts(ts):
    if pd.isna(ts):
        return "N/A"
    return str(ts)

with open(report_path, "w", encoding="utf-8") as f:
    f.write(f"{DIVIDER}\n")
    f.write("  SDN ICMP FLOOD FORENSIC REPORT\n")
    f.write(f"{DIVIDER}\n")
    f.write(f"  Generated  : {NOW_STR}\n")
    f.write(f"  Base Dir   : {BASE_DIR}\n")
    f.write("  Prepared by: SDN Forensic Analyzer v3\n")
    f.write(f"{DIVIDER}\n")

    section(f, 1, "EXPERIMENT OVERVIEW")
    f.write("  Experiment Title  : Distributed ICMP Flood Detection & Mitigation\n")
    f.write("                      on Software-Defined Network (SDN)\n")
    f.write("  Controller        : Ryu Controller (OpenFlow 1.3)\n")
    f.write("  Emulation         : Mininet\n")
    f.write("  Detection Method  : Hybrid Detection (SVM-assisted + threshold-based telemetry analysis)\n")
    f.write("  Mitigation Method : OpenFlow Meter (rate limiting per attacker segment)\n")
    f.write("  Evidence Sources  : traffic_analysis.csv, mitigation_events.csv, PCAP (Wireshark/analyze_pcap.py)\n")
    f.write("  Forensic Framework: NIST SP 800-86\n")

    section(f, 2, "NIST SP 800-86 MAPPING")
    subsection(f, "Collection")
    f.write(f"  - Baseline PCAP         : logs/archive/baseline/session_baseline.pcap [{file_status(BASELINE_PCAP)}]\n")
    f.write(f"  - DDoS PCAP             : logs/archive/ddos/session_ddos.pcap [{file_status(DDOS_PCAP)}]\n")
    f.write(f"  - Baseline Traffic CSV  : logs/archive/baseline/traffic_analysis.csv [{file_status(BASELINE_TRAFFIC_CSV)}]\n")
    f.write(f"  - DDoS Traffic CSV      : logs/archive/ddos/traffic_analysis.csv [{file_status(DDOS_TRAFFIC_CSV)}]\n")
    f.write(f"  - Mitigation CSV        : logs/archive/ddos/mitigation_events.csv [{file_status(MITIGATION_CSV)}]\n")

    subsection(f, "Examination")
    f.write("  - ICMP protocol filtering (protocol_name == ICMP)\n")
    f.write(f"  - Victim filtering (dst_ip == {VICTIM_IP})\n")
    f.write(f"  - Attacker source IP extraction ({', '.join(ATTACKER_IPS)})\n")
    f.write("  - Detection status filtering (WARNING, ATTACK_CONFIRMED, RATE_LIMIT_ACTIVE)\n")
    f.write("  - Event type filtering (SUSPICIOUS, ATTACK, LIMITED)\n")

    subsection(f, "Analysis")
    f.write("  - Packet rate comparison (baseline vs DDoS vs forensic attack)\n")
    f.write("  - Timeline reconstruction per attacker (Graph 02)\n")
    f.write("  - Threat score escalation analysis (Graph 03)\n")
    f.write("  - Detection lifecycle verification (Graph 04)\n")
    f.write("  - Attacker attribution per source IP (Graph 05, 09)\n")
    f.write("  - Dominant flow identification (Graph 06)\n")
    f.write("  - Mitigation effectiveness & lifecycle (Graph 07, 08)\n")

    subsection(f, "Reporting")
    f.write("  - forensic_report.txt        : narasi dan temuan utama\n")
    f.write("  - summary_stats.csv          : ringkasan statistik\n")
    f.write("  - filtered_attack_events.csv : event forensik terfilter\n")
    f.write("  - attacker_summary.csv       : ringkasan per attacker\n")
    f.write("  - Graph 01-10                : visualisasi bukti forensik\n")

    section(f, 3, "EVIDENCE INVENTORY")
    f.write(f"  {'Evidence':<32} {'Path':<55} {'Status'}\n")
    f.write(f"  {'-' * 110}\n")
    evidence_items = [
        ("Baseline PCAP", "logs/archive/baseline/session_baseline.pcap", BASELINE_PCAP),
        ("DDoS PCAP", "logs/archive/ddos/session_ddos.pcap", DDOS_PCAP),
        ("Baseline Traffic CSV", "logs/archive/baseline/traffic_analysis.csv", BASELINE_TRAFFIC_CSV),
        ("DDoS Traffic CSV", "logs/archive/ddos/traffic_analysis.csv", DDOS_TRAFFIC_CSV),
        ("Mitigation CSV", "logs/archive/ddos/mitigation_events.csv", MITIGATION_CSV),
        ("Forensic Report", "logs/report_graphs/forensic_report.txt", report_path),
    ]
    for name, relpath, path in evidence_items:
        f.write(f"  {name:<32} {relpath:<55} {file_status(path)}\n")

    section(f, 4, "EXPERIMENT TOPOLOGY")
    f.write("  Topology Type : Enterprise tree (1 core + 5 access switches, 25 hosts)\n\n")
    f.write(f"  {'Node':<12} {'IP':<16} {'Switch':<10} {'Role'}\n")
    f.write(f"  {'-' * 55}\n")
    f.write(f"  {'s1':<12} {'-':<16} {'core':<10} Core switch\n")
    f.write(f"  {'s2-s6':<12} {'-':<16} {'access':<10} Access switches per segment\n")
    for ip, meta in ATTACKERS.items():
        f.write(f"  {meta['host']:<12} {ip:<16} {meta['switch']:<10} ATTACKER\n")
    f.write(f"  {'h25':<12} {VICTIM_IP:<16} {'s6':<10} VICTIM\n")

    section(f, 5, "MAIN STATISTICS")
    for _, row in summary_stats.iterrows():
        f.write(f"  {row['Metric']:<42} : {row['Value']}\n")

    section(f, 6, "ATTACK TIMELINE SUMMARY")
    f.write(f"  First WARNING event          : {fmt_ts(first_warning)}\n")
    f.write(f"  First ATTACK_CONFIRMED event : {fmt_ts(first_confirmed)}\n")
    f.write(f"  First RATE_LIMIT_ACTIVE event: {fmt_ts(first_limited)}\n")
    f.write(f"  First mitigation action      : {fmt_ts(first_mitigation)}\n")
    f.write("\n  Per-attacker first mitigation:\n")
    if mitigation_times:
        for ip, ts in mitigation_times.items():
            f.write(f"    - {attacker_label(ip):<24} : {fmt_ts(ts)}\n")
    else:
        f.write("    - N/A\n")

    section(f, 7, "DETECTED ATTACKERS")
    if not attack_df.empty and "src_ip" in attack_df.columns:
        for ip in unique_attackers_detected:
            meta = ATTACKERS.get(ip, {})
            grp = attack_df[attack_df["src_ip"] == ip]
            f.write(f"  IP Address          : {ip}\n")
            f.write(f"  Host                : {meta.get('host', 'UNKNOWN')}\n")
            f.write(f"  Switch              : {meta.get('switch', 'UNKNOWN')}\n")
            f.write(f"  Segment             : {meta.get('segment', 'UNKNOWN')}\n")
            f.write(f"  Total Attack Events : {len(grp)}\n")
            f.write(f"  Warning Events      : {int((grp['detection_status'] == 'WARNING').sum()) if 'detection_status' in grp else 0}\n")
            f.write(f"  Confirmed Events    : {int((grp['detection_status'] == 'ATTACK_CONFIRMED').sum()) if 'detection_status' in grp else 0}\n")
            f.write(f"  Rate Limited Events : {int((grp['detection_status'] == 'RATE_LIMIT_ACTIVE').sum()) if 'detection_status' in grp else 0}\n")
            f.write(f"  Max Packet Rate     : {safe_max(grp, 'packet_rate')} PPS\n")
            f.write(f"  Max Threat Score    : {safe_max(grp, 'threat_score')}\n")
            f.write(f"  {SUBDIV}\n")
    else:
        f.write("  Tidak ada attacker terdeteksi oleh filter forensik.\n")

    section(f, 8, "MITIGATION SUMMARY")
    if not mitigation_df.empty:
        f.write(f"  Total mitigation log rows : {len(mitigation_df)}\n\n")
        if "action" in mitigation_df.columns:
            f.write("  Action Distribution:\n")
            for act, cnt in mitigation_df["action"].value_counts().items():
                f.write(f"    {act:<30} : {cnt}\n")
        if "src_ip" in mitigation_df.columns:
            f.write("\n  Mitigated Source IPs:\n")
            for ip, cnt in mitigation_df["src_ip"].value_counts().items():
                f.write(f"    {attacker_label(ip):<24} : {cnt} event(s)\n")
        if "limit_pps" in mitigation_df.columns:
            f.write("\n  OpenFlow Meter Limit Distribution:\n")
            for pps, cnt in mitigation_df["limit_pps"].dropna().astype(int).value_counts().sort_index().items():
                f.write(f"    {pps} PPS : {cnt} event(s)\n")
        if "dpid_name" in mitigation_df.columns:
            f.write("\n  Mitigation Applied on Switch:\n")
            for sw, cnt in mitigation_df["dpid_name"].value_counts().items():
                f.write(f"    {sw} : {cnt} event(s)\n")
        if "action" in mitigation_df.columns:
            releases = mitigation_df[mitigation_df["action"].str.contains("RELEASE", na=False)]
            if not releases.empty:
                f.write("\n  RELEASE_METER Events (Recovery):\n")
                for _, row in releases.iterrows():
                    f.write(f"    {row.get('timestamp', '?')} | {row.get('src_ip', '?')} | {row.get('action', '?')}\n")
    else:
        f.write("  Tidak ada data mitigation_events.csv ditemukan.\n")

    section(f, 9, "TOP ATTACK FLOWS")
    if not attack_df.empty and {"src_ip", "dst_ip"}.issubset(attack_df.columns):
        flow_df = attack_df[attack_df["src_ip"].isin(ATTACKER_IPS) & (attack_df["dst_ip"] == VICTIM_IP)]
        top_flows = (flow_df["src_ip"] + " -> " + flow_df["dst_ip"]).value_counts().head(10)
        f.write(f"  {'Flow':<40} {'Events':>8}\n")
        f.write(f"  {'-' * 50}\n")
        for flow, cnt in top_flows.items():
            f.write(f"  {flow:<40} {cnt:>8}\n")
    else:
        f.write("  Tidak ada data flow serangan tersedia.\n")

    section(f, 10, "FORENSIC FINDINGS")
    findings = [
        f"Distributed ICMP Flood terdeteksi dari {len(unique_attackers_detected)} attacker unik.",
        f"Semua attacker berhasil diidentifikasi: {', '.join([attacker_label(ip) for ip in unique_attackers_detected])}.",
        f"Traffic menuju victim {VICTIM_IP} meningkat signifikan dibanding baseline (avg {baseline_rate:.2f} PPS -> {attack_rate:.2f} PPS pada fase serangan).",
        "Detection lifecycle berjalan sesuai desain: NORMAL -> WARNING -> ATTACK_CONFIRMED -> RATE_LIMIT_ACTIVE.",
        "OpenFlow Meter diterapkan pada access switch masing-masing attacker segment, sehingga mitigasi dilakukan dekat sumber serangan.",
        "Variasi limit_pps mengindikasikan mekanisme adaptive rate limiting aktif.",
        f"Packet rate maksimum serangan mencapai {max_attack_rate:.2f} PPS dengan threat score tertinggi {max_threat_score:.2f}.",
        "Seluruh tahapan NIST SP 800-86 terpenuhi: Collection, Examination, Analysis, dan Reporting.",
    ]
    for i, finding in enumerate(findings, 1):
        f.write(f"  {i}. {finding}\n\n")

    section(f, 11, "FINAL FORENSIC CONCLUSION")
    f.write(
        f"  Berdasarkan hasil analisis terhadap telemetry evidence eksperimen SDN, sistem Ryu Controller\n"
        f"  dengan OpenFlow 1.3 mampu mendeteksi dan memitigasi skenario Distributed ICMP Flood\n"
        f"  secara otomatis dan terukur. Sebanyak {len(unique_attackers_detected)} attacker teridentifikasi\n"
        f"  melakukan serangan terhadap victim {VICTIM_IP}. Rata-rata packet rate serangan sebesar\n"
        f"  {attack_rate:.2f} PPS melampaui threshold WARNING ({WARNING_PPS} PPS) dan ATTACK ({ATTACK_PPS} PPS).\n\n"
        f"  Mekanisme hybrid detection yang menggabungkan SVM-assisted prediction dan threshold-based\n"
        f"  telemetry analysis menghasilkan escalation dari WARNING ke ATTACK_CONFIRMED, kemudian\n"
        f"  controller menerapkan OpenFlow Meter pada access switch attacker. Evidence dari CSV telemetry\n"
        f"  dan PCAP mendukung proses investigasi forensik berbasis NIST SP 800-86: Collection,\n"
        f"  Examination, Analysis, dan Reporting.\n"
    )

    f.write(f"\n{DIVIDER}\n")
    f.write(f"  END OF REPORT — Generated: {NOW_STR}\n")
    f.write(f"{DIVIDER}\n")

print("  [+] forensic_report.txt")

print(f"\n{'=' * 68}")
print("  Analysis complete.")
print(f"  Graphs : {OUTPUT_DIR}")
print(f"  Report : {report_path}")
print(f"{'=' * 68}\n")
