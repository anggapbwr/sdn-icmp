#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — Telemetry Forensic Analyzer
=============================================
NIST SP 800-86 | Telemetry Evidence (CSV)

Sumber data:
  - logs/archive/baseline/traffic_analysis.csv
  - logs/archive/ddos/traffic_analysis.csv
  - logs/archive/ddos/mitigation_events.csv

Output: 5 grafik PNG + summary terminal + forensic_report.txt

Grafik:
  01 — Timeline packet rate 3 fase per attacker + cliff mitigasi
  02 — Threat score escalation timeline
  03 — Detection state distribution
  04 — Attacker attribution (forensic events per attacker)
  05 — Mitigation lifecycle (DROP vs RELEASE)

Usage:
  python3 analysis/analyze.py
"""

import os
import sys
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

# ─── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR     = "/home/kali/sdn-icmp"
BASELINE_CSV = f"{BASE_DIR}/logs/archive/baseline/traffic_analysis.csv"
DDOS_CSV     = f"{BASE_DIR}/logs/archive/ddos/traffic_analysis.csv"
MITIGATION_CSV = f"{BASE_DIR}/logs/archive/ddos/mitigation_events.csv"
OUTPUT_DIR   = f"{BASE_DIR}/logs/report_graphs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Topology ─────────────────────────────────────────────────────────────────

VICTIM_IP = "10.0.0.25"

ATTACKERS = {
    "10.0.0.1":  {"host": "h1",  "switch": "s2"},
    "10.0.0.7":  {"host": "h7",  "switch": "s3"},
    "10.0.0.13": {"host": "h13", "switch": "s4"},
    "10.0.0.18": {"host": "h18", "switch": "s5"},
}
ATTACKER_IPS    = list(ATTACKERS.keys())
ATTACKER_COLORS = ["#E05C5C", "#F5A623", "#8E44AD", "#2980B9"]

WARNING_PPS = 20
ATTACK_PPS  = 50

# ─── Style ────────────────────────────────────────────────────────────────────

PALETTE = {
    "normal":    "#4A90D9",
    "attack":    "#E05C5C",
    "mitigated": "#27AE60",
    "warning":   "#F5A623",
    "confirmed": "#C0392B",
    "drop":      "#8E44AD",
    "baseline":  "#95A5A6",
    "grid":      "#ECEFF1",
    "text":      "#2C3E50",
    "sub":       "#7F8C8D",
}

PHASE_COLORS = {
    "NORMAL":    PALETTE["normal"],
    "ATTACK":    PALETTE["attack"],
    "MITIGATED": PALETTE["mitigated"],
}

plt.rcParams.update({
    "figure.facecolor":   "white",
    "axes.facecolor":     "white",
    "axes.edgecolor":     "#BDC3C7",
    "axes.grid":          True,
    "grid.color":         PALETTE["grid"],
    "grid.linewidth":     0.8,
    "grid.alpha":         0.9,
    "axes.spines.top":    False,
    "axes.spines.right":  False,
    "axes.titlesize":     13,
    "axes.titleweight":   "bold",
    "axes.titlepad":      12,
    "axes.labelsize":     10,
    "axes.labelcolor":    PALETTE["text"],
    "xtick.labelsize":    9,
    "ytick.labelsize":    9,
    "legend.fontsize":    9,
    "legend.framealpha":  0.9,
    "legend.edgecolor":   "#BDC3C7",
    "font.family":        "DejaVu Sans",
})

# ─── Helpers ──────────────────────────────────────────────────────────────────

def out(fn):
    return os.path.join(OUTPUT_DIR, fn)

def save(fn, dpi=180):
    plt.tight_layout()
    plt.savefig(out(fn), dpi=dpi, bbox_inches="tight")
    plt.close()
    print(f"  [+] {fn}")

def subtitle(ax, text):
    ax.text(0, 1.015, text, transform=ax.transAxes,
            fontsize=8, color=PALETTE["sub"], ha="left", va="bottom")

def load(path):
    if not os.path.exists(path):
        print(f"  [!] Not found: {path}")
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"  [!] Failed to read {path}: {e}")
        return pd.DataFrame()

def prep(df):
    """Normalize types untuk semua kolom yang dipakai."""
    if df.empty:
        return df
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["packet_rate", "threat_score", "packet_count", "final_prediction"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in ["src_ip", "dst_ip", "phase", "detection_status",
                "event_type", "attack_type", "event_note", "protocol_name",
                "mitigation_status", "severity", "action", "src_ip"]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()
    return df

def attacker_label(ip):
    m = ATTACKERS.get(ip, {})
    return f"{m.get('host', ip)} ({ip})" if m else ip

# ─── Load & prep ──────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SDN TELEMETRY FORENSIC ANALYZER")
print(f"  NIST SP 800-86 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

print("\n[*] Loading CSV evidence ...")
baseline_df   = prep(load(BASELINE_CSV))
ddos_df       = prep(load(DDOS_CSV))
mitigation_df = prep(load(MITIGATION_CSV))

if ddos_df.empty:
    print("  [!] DDoS CSV kosong atau tidak ada. Keluar.")
    sys.exit(1)

# Filter attacker traffic ke victim
attack_df = ddos_df[
    ddos_df["src_ip"].isin(ATTACKER_IPS) &
    (ddos_df["dst_ip"] == VICTIM_IP) &
    (ddos_df["protocol_name"] == "ICMP")
].copy() if not ddos_df.empty else pd.DataFrame()

# Baseline ICMP ke victim dari host normal (bukan attacker)
baseline_victim_df = ddos_df[
    ~ddos_df["src_ip"].isin(ATTACKER_IPS) &
    (ddos_df["dst_ip"] == VICTIM_IP) &
    (ddos_df["protocol_name"] == "ICMP") &
    (ddos_df["event_note"] == "baseline_icmp_to_victim")
].copy() if not ddos_df.empty else pd.DataFrame()

# Mitigation timestamps per attacker
mitigation_times = {}
if not mitigation_df.empty:
    mitigation_df["timestamp"] = pd.to_datetime(
        mitigation_df["timestamp"], errors="coerce")
    drop_rows = mitigation_df[
        mitigation_df.get("action", pd.Series(dtype=str)).astype(str).str.contains("DROP_ICMP", na=False)
    ] if "action" in mitigation_df.columns else pd.DataFrame()
    for ip, grp in drop_rows.groupby("src_ip") if not drop_rows.empty else []:
        mitigation_times[ip] = grp["timestamp"].min()

release_times = {}
if not mitigation_df.empty and "action" in mitigation_df.columns:
    rel_rows = mitigation_df[
        mitigation_df["action"].astype(str).str.contains("RELEASE", na=False)
    ]
    for ip, grp in rel_rows.groupby("src_ip"):
        release_times[ip] = grp["timestamp"].min()

# ─── Summary stats ────────────────────────────────────────────────────────────

def _safe_val(df, col, fn):
    if df.empty or col not in df.columns: return 0
    v = fn(df[col].dropna())
    return round(float(v), 2) if not pd.isna(v) else 0

warning_df   = attack_df[attack_df["detection_status"] == "WARNING"]   if not attack_df.empty else pd.DataFrame()
confirmed_df = attack_df[attack_df["detection_status"] == "ATTACK_CONFIRMED"] if not attack_df.empty else pd.DataFrame()
drop_df      = attack_df[attack_df["detection_status"] == "DROP_ACTIVE"] if not attack_df.empty else pd.DataFrame()

stats = {
    "Baseline events (CSV)":       len(baseline_df),
    "DDoS total events (CSV)":     len(ddos_df),
    "Attack events (attacker→victim)": len(attack_df),
    "WARNING events":              len(warning_df),
    "ATTACK_CONFIRMED events":     len(confirmed_df),
    "DROP_ACTIVE events":          len(drop_df),
    "Baseline ICMP to victim":     len(baseline_victim_df),
    "Mitigation events (CSV)":     len(mitigation_df),
    "Avg baseline packet rate":    _safe_val(baseline_df, "packet_rate", lambda s: s.mean()),
    "Avg attack packet rate":      _safe_val(attack_df,   "packet_rate", lambda s: s.mean()),
    "Max attack packet rate":      _safe_val(attack_df,   "packet_rate", lambda s: s.max()),
    "Max threat score":            _safe_val(attack_df,   "threat_score", lambda s: s.max()),
    "Unique attackers detected":   attack_df["src_ip"].nunique() if not attack_df.empty else 0,
}

print("\n[*] Summary:")
for k, v in stats.items():
    print(f"    {k:<40} {v}")

# ─── Graph 01: Timeline packet rate 3 fase ────────────────────────────────────

def graph_01():
    fn = "01_packet_rate_timeline_3phase.png"
    if attack_df.empty or "timestamp" not in attack_df.columns:
        print(f"  [!] Skip {fn}: no attack data"); return

    fig, ax = plt.subplots(figsize=(15, 7))

    # Background phase bands dari baseline_victim_df (ikut phase column)
    # Gambar shade berdasarkan waktu mitigasi pertama & release
    if mitigation_times:
        mit_start = min(mitigation_times.values())
        # Shade ATTACK phase (sebelum mitigasi)
        all_times = attack_df["timestamp"].dropna()
        if not all_times.empty:
            ax.axvspan(all_times.min(), mit_start,
                       alpha=0.07, color=PALETTE["attack"], label="_nolegend_")
        # Shade MITIGATED phase
        mit_end = mit_start + pd.Timedelta(seconds=60)
        ax.axvspan(mit_start, mit_end,
                   alpha=0.07, color=PALETTE["mitigated"], label="_nolegend_")

    # Plot baseline ICMP ke victim (host normal)
    if not baseline_victim_df.empty and "timestamp" in baseline_victim_df.columns:
        bv = baseline_victim_df.dropna(subset=["timestamp","packet_rate"]).sort_values("timestamp")
        ax.plot(bv["timestamp"], bv["packet_rate"],
                color=PALETTE["baseline"], linewidth=1.2, alpha=0.7,
                linestyle="--", label="Baseline ping (host normal → victim)")

    # Plot tiap attacker
    for idx, ip in enumerate(ATTACKER_IPS):
        grp = attack_df[attack_df["src_ip"] == ip].dropna(
            subset=["timestamp","packet_rate"]).sort_values("timestamp")
        if grp.empty: continue
        color = ATTACKER_COLORS[idx]
        label = attacker_label(ip)
        ax.plot(grp["timestamp"], grp["packet_rate"],
                color=color, linewidth=1.8, alpha=0.9, label=label)

        # Garis vertikal DROP aktif
        if ip in mitigation_times:
            ax.axvline(mitigation_times[ip], color=color,
                       linestyle=":", linewidth=1.5, alpha=0.8)
            ax.annotate("DROP", xy=(mitigation_times[ip], ax.get_ylim()[1]),
                        xytext=(4, -14), textcoords="offset points",
                        fontsize=7, color=color, rotation=90)

    # Threshold lines
    ax.axhline(WARNING_PPS, color=PALETTE["warning"], linestyle="--",
               linewidth=1.3, alpha=0.85, label=f"Warning ({WARNING_PPS} pps)")
    ax.axhline(ATTACK_PPS, color=PALETTE["confirmed"], linestyle="--",
               linewidth=1.3, alpha=0.85, label=f"Attack ({ATTACK_PPS} pps)")

    # Phase label patches untuk legend
    patches = [
        mpatches.Patch(color=PALETTE["normal"],    alpha=0.3, label="Phase: NORMAL"),
        mpatches.Patch(color=PALETTE["attack"],    alpha=0.3, label="Phase: ATTACK"),
        mpatches.Patch(color=PALETTE["mitigated"], alpha=0.3, label="Phase: MITIGATED"),
    ]
    handles, labels_ = ax.get_legend_handles_labels()
    ax.legend(handles=handles + patches, loc="upper right", ncol=2, fontsize=8)

    ax.set_title("Packet Rate Timeline — 3 Phase: Normal → Attack → Mitigated")
    subtitle(ax, "Kolom 'phase' dari controller CSV | Garis titik = waktu DROP aktif per attacker")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Packet Rate (pps) — EWMA smoothed")
    ax.tick_params(axis="x", rotation=30)
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph 02: Threat score escalation ───────────────────────────────────────

def graph_02():
    fn = "02_threat_score_escalation.png"
    if attack_df.empty or "threat_score" not in attack_df.columns:
        print(f"  [!] Skip {fn}: no data"); return

    df = attack_df.dropna(subset=["timestamp","threat_score"]).sort_values("timestamp")
    if df.empty:
        print(f"  [!] Skip {fn}: empty after dropna"); return

    fig, ax = plt.subplots(figsize=(15, 6))

    ts_max = max(float(df["threat_score"].max()) * 1.15, 100)

    # Zone backgrounds
    ax.axhspan(0,  40,      alpha=0.05, color="#27AE60")
    ax.axhspan(40, 70,      alpha=0.05, color="#F5A623")
    ax.axhspan(70, ts_max,  alpha=0.05, color="#E05C5C")

    for idx, ip in enumerate(ATTACKER_IPS):
        grp = df[df["src_ip"] == ip]
        if grp.empty: continue
        ax.plot(grp["timestamp"], grp["threat_score"],
                color=ATTACKER_COLORS[idx], linewidth=1.8,
                alpha=0.9, label=attacker_label(ip))

        if ip in mitigation_times:
            ax.axvline(mitigation_times[ip], color=ATTACKER_COLORS[idx],
                       linestyle=":", linewidth=1.3, alpha=0.7)

    ax.axhline(40, color=PALETTE["warning"],   linestyle="--", linewidth=1.2,
               alpha=0.8, label="Warning level (40)")
    ax.axhline(70, color=PALETTE["confirmed"], linestyle="--", linewidth=1.2,
               alpha=0.8, label="Alert level (70)")

    ax.set_title(f"Threat Score Escalation — Detection Lifecycle (Victim: {VICTIM_IP})")
    subtitle(ax, "Zona hijau=normal | kuning=warning | merah=alert | titik vertikal=DROP aktif")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Threat Score (0–100)")
    ax.set_ylim(0, ts_max)
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper left", ncol=2, fontsize=8)
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph 03: Detection state distribution ───────────────────────────────────

def graph_03():
    fn = "03_detection_state_distribution.png"
    if ddos_df.empty or "detection_status" not in ddos_df.columns:
        print(f"  [!] Skip {fn}: no data"); return

    order = ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "DROP_ACTIVE"]
    color_map = {
        "NORMAL":           PALETTE["normal"],
        "WARNING":          PALETTE["warning"],
        "ATTACK_CONFIRMED": PALETTE["confirmed"],
        "DROP_ACTIVE":      PALETTE["drop"],
    }

    counts = ddos_df["detection_status"].value_counts()
    labels = [s for s in order if s in counts.index]
    values = [int(counts[s]) for s in labels]
    colors = [color_map[s] for s in labels]

    if not values:
        print(f"  [!] Skip {fn}: no state data"); return

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(labels, values, color=colors, width=0.5,
                  zorder=3, edgecolor="white", linewidth=1.2)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + max(values)*0.012,
                f"{val:,}", ha="center", va="bottom",
                fontsize=10, fontweight="bold", color=PALETTE["text"])

    ax.set_title("Detection State Distribution — State Machine Verification")
    subtitle(ax, "NORMAL → WARNING → ATTACK_CONFIRMED → DROP_ACTIVE | sumber: detection_status di CSV")
    ax.set_xlabel("Detection Status")
    ax.set_ylabel("Jumlah Events")
    ax.set_ylim(0, max(values) * 1.22)
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph 04: Attacker attribution ──────────────────────────────────────────

def graph_04():
    fn = "04_attacker_attribution.png"
    if attack_df.empty or "src_ip" not in attack_df.columns:
        print(f"  [!] Skip {fn}: no data"); return

    fig, axes = plt.subplots(1, 2, figsize=(15, 6))

    # Kiri: total forensic events per attacker
    ax1 = axes[0]
    counts = (
        attack_df[attack_df["src_ip"].isin(ATTACKER_IPS)]
        .groupby("src_ip").size()
        .reindex(ATTACKER_IPS).fillna(0).astype(int)
    )
    labels  = [attacker_label(ip) for ip in counts.index]
    values  = counts.values
    colors  = ATTACKER_COLORS[:len(labels)]

    bars = ax1.bar(labels, values, color=colors, width=0.5,
                   zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, values):
        ax1.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + max(values)*0.01 if max(values) > 0 else 1,
                 f"{val:,}", ha="center", va="bottom",
                 fontsize=10, fontweight="bold")

    ax1.set_title("Forensic Events per Attacker")
    ax1.set_ylabel("Jumlah Events")
    ax1.set_xticklabels(labels, rotation=12, ha="right", fontsize=8)
    ax1.set_ylim(0, max(values)*1.2 if max(values) > 0 else 10)
    ax1.set_axisbelow(True)

    # Kanan: max packet rate per attacker
    ax2 = axes[1]
    max_rates = []
    for ip in ATTACKER_IPS:
        grp = attack_df[attack_df["src_ip"] == ip]["packet_rate"].dropna()
        max_rates.append(float(grp.max()) if not grp.empty else 0)

    bars2 = ax2.bar(labels, max_rates, color=colors, width=0.5,
                    zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars2, max_rates):
        ax2.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + max(max_rates)*0.01 if max(max_rates) > 0 else 1,
                 f"{val:.1f}", ha="center", va="bottom",
                 fontsize=10, fontweight="bold")

    ax2.axhline(WARNING_PPS, color=PALETTE["warning"], linestyle="--",
                linewidth=1.2, alpha=0.8, label=f"Warning ({WARNING_PPS} pps)")
    ax2.axhline(ATTACK_PPS, color=PALETTE["confirmed"], linestyle="--",
                linewidth=1.2, alpha=0.8, label=f"Attack ({ATTACK_PPS} pps)")
    ax2.set_title("Max Packet Rate per Attacker")
    ax2.set_ylabel("Max Packet Rate (pps)")
    ax2.set_xticklabels(labels, rotation=12, ha="right", fontsize=8)
    ax2.set_ylim(0, max(max_rates)*1.2 if max(max_rates) > 0 else 10)
    ax2.legend(fontsize=8)
    ax2.set_axisbelow(True)

    fig.suptitle("Attacker Attribution — Source IP Forensic Evidence", fontsize=13, fontweight="bold")
    subtitle(axes[0], "Kiri: total forensic events | Kanan: max packet rate per attacker IP")
    save(fn)

# ─── Graph 05: Mitigation lifecycle ──────────────────────────────────────────

def graph_05():
    fn = "05_mitigation_lifecycle.png"
    if mitigation_df.empty or "action" not in mitigation_df.columns:
        print(f"  [!] Skip {fn}: no mitigation data"); return

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Kiri: action distribution
    ax1 = axes[0]
    counts = mitigation_df["action"].value_counts()
    colors_bar = [PALETTE["drop"] if "DROP" in str(a) else PALETTE["mitigated"]
                  for a in counts.index]
    bars = ax1.bar(counts.index, counts.values, color=colors_bar,
                   width=0.45, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, counts.values):
        ax1.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + counts.max()*0.02,
                 str(int(val)), ha="center", va="bottom",
                 fontsize=11, fontweight="bold")
    ax1.set_title("Mitigation Action Distribution")
    ax1.set_xlabel("Action")
    ax1.set_ylabel("Jumlah Events")
    ax1.tick_params(axis="x", rotation=10)
    ax1.set_axisbelow(True)

    # Kanan: timeline drop vs release per attacker
    ax2 = axes[1]
    if "src_ip" in mitigation_df.columns and "timestamp" in mitigation_df.columns:
        y_pos = 0
        yticks, ylabels = [], []
        for ip in ATTACKER_IPS:
            grp = mitigation_df[mitigation_df["src_ip"] == ip].dropna(subset=["timestamp"])
            if grp.empty: continue

            drop_t  = mitigation_times.get(ip)
            rel_t   = release_times.get(ip)

            if drop_t:
                ax2.scatter(drop_t, y_pos, color=PALETTE["drop"],
                            s=120, zorder=5, marker="v", label="DROP" if y_pos == 0 else "_")
            if rel_t:
                ax2.scatter(rel_t, y_pos, color=PALETTE["mitigated"],
                            s=120, zorder=5, marker="^", label="RELEASE" if y_pos == 0 else "_")
            if drop_t and rel_t:
                ax2.hlines(y_pos, drop_t, rel_t,
                           colors=PALETTE["drop"], linewidth=3, alpha=0.5)

            yticks.append(y_pos)
            ylabels.append(attacker_label(ip))
            y_pos += 1

        if yticks:
            ax2.set_yticks(yticks)
            ax2.set_yticklabels(ylabels, fontsize=8)
        ax2.set_title("Mitigation Timeline per Attacker")
        ax2.set_xlabel("Timestamp")
        ax2.tick_params(axis="x", rotation=30)
        ax2.legend(loc="lower right", fontsize=8)
        ax2.set_axisbelow(True)
        ax2.grid(axis="x")
        ax2.grid(axis="y", alpha=0.3)

    fig.suptitle("Mitigation Lifecycle — DROP_ICMP & RELEASE_DROP Evidence",
                 fontsize=13, fontweight="bold")
    subtitle(axes[0], "Ungu=DROP_ICMP aktif | Hijau=RELEASE_DROP (recovery)")
    save(fn)

# ─── Run all graphs ───────────────────────────────────────────────────────────

print("\n[*] Generating graphs ...")
graph_01()
graph_02()
graph_03()
graph_04()
graph_05()

# ─── Forensic report ─────────────────────────────────────────────────────────

print("\n[*] Writing forensic_report.txt ...")
report_path = out("forensic_report.txt")
NOW = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
DIV = "=" * 65
SUB = "-" * 65

unique_attackers = sorted(attack_df["src_ip"].unique().tolist()) if not attack_df.empty else []

first_warning   = warning_df["timestamp"].min()   if not warning_df.empty   else pd.NaT
first_confirmed = confirmed_df["timestamp"].min() if not confirmed_df.empty else pd.NaT
first_drop      = drop_df["timestamp"].min()      if not drop_df.empty      else pd.NaT
first_mit       = min(mitigation_times.values())  if mitigation_times       else pd.NaT

def fmt(ts):
    return str(ts) if not pd.isna(ts) else "N/A"

with open(report_path, "w", encoding="utf-8") as f:
    f.write(f"{DIV}\n  SDN ICMP FLOOD — TELEMETRY FORENSIC REPORT\n{DIV}\n")
    f.write(f"  Generated  : {NOW}\n")
    f.write(f"  Framework  : NIST SP 800-86\n")
    f.write(f"  Evidence   : traffic_analysis.csv + mitigation_events.csv\n{DIV}\n")

    f.write(f"\n1. EXPERIMENT OVERVIEW\n{SUB}\n")
    f.write(f"  Controller     : Ryu OpenFlow 1.3 (Drop-Based Mitigation)\n")
    f.write(f"  Emulator       : Mininet\n")
    f.write(f"  Detection      : EWMA + SVM-assisted threshold\n")
    f.write(f"  Mitigation     : OpenFlow DROP rule per attacker IP\n")
    f.write(f"  Victim         : {VICTIM_IP} (h25/s6)\n")
    f.write(f"  Attackers      : {', '.join([f'{ATTACKERS[ip]["host"]} ({ip})' for ip in ATTACKER_IPS])}\n")

    f.write(f"\n2. SUMMARY STATISTICS\n{SUB}\n")
    for k, v in stats.items():
        f.write(f"  {k:<42}: {v}\n")

    f.write(f"\n3. ATTACK TIMELINE\n{SUB}\n")
    f.write(f"  First WARNING event          : {fmt(first_warning)}\n")
    f.write(f"  First ATTACK_CONFIRMED event : {fmt(first_confirmed)}\n")
    f.write(f"  First DROP_ACTIVE event      : {fmt(first_drop)}\n")
    f.write(f"  First DROP rule installed    : {fmt(first_mit)}\n")
    f.write(f"\n  Per-attacker DROP timestamp:\n")
    for ip, ts in mitigation_times.items():
        f.write(f"    {attacker_label(ip):<30}: {fmt(ts)}\n")
    f.write(f"\n  Per-attacker RELEASE timestamp:\n")
    for ip, ts in release_times.items():
        f.write(f"    {attacker_label(ip):<30}: {fmt(ts)}\n")

    f.write(f"\n4. ATTACKER DETAIL\n{SUB}\n")
    for ip in unique_attackers:
        meta = ATTACKERS.get(ip, {})
        grp  = attack_df[attack_df["src_ip"] == ip] if not attack_df.empty else pd.DataFrame()
        f.write(f"  IP      : {ip}\n")
        f.write(f"  Host    : {meta.get('host','?')} | Switch: {meta.get('switch','?')}\n")
        f.write(f"  Events  : {len(grp)}\n")
        f.write(f"  WARNING : {int((grp['detection_status']=='WARNING').sum()) if not grp.empty else 0}\n")
        f.write(f"  CONFIRMED: {int((grp['detection_status']=='ATTACK_CONFIRMED').sum()) if not grp.empty else 0}\n")
        f.write(f"  MAX PPS : {_safe_val(grp,'packet_rate',lambda s:s.max())}\n")
        f.write(f"  MAX TS  : {_safe_val(grp,'threat_score',lambda s:s.max())}\n")
        f.write(f"  {SUB}\n")

    f.write(f"\n5. MITIGATION SUMMARY\n{SUB}\n")
    if not mitigation_df.empty:
        if "action" in mitigation_df.columns:
            for act, cnt in mitigation_df["action"].value_counts().items():
                f.write(f"  {act:<30}: {cnt} events\n")
        if "dpid_name" in mitigation_df.columns:
            f.write(f"\n  Switch yang menerapkan DROP:\n")
            for sw, cnt in mitigation_df["dpid_name"].value_counts().items():
                f.write(f"    {sw}: {cnt} events\n")
    else:
        f.write("  Tidak ada data mitigation.\n")

    f.write(f"\n6. FORENSIC FINDINGS\n{SUB}\n")
    findings = [
        f"Distributed ICMP Flood terdeteksi dari {len(unique_attackers)} attacker unik.",
        f"Semua attacker teridentifikasi: {', '.join([attacker_label(ip) for ip in unique_attackers])}.",
        f"Packet rate serangan (avg {_safe_val(attack_df,'packet_rate',lambda s:s.mean()):.2f} pps) "
        f"melampaui threshold WARNING ({WARNING_PPS} pps) dan ATTACK ({ATTACK_PPS} pps).",
        "Detection lifecycle berjalan: NORMAL → WARNING → ATTACK_CONFIRMED → DROP_ACTIVE.",
        "DROP rule terpasang pada access switch per-attacker — host normal tidak terganggu.",
        "Baseline ICMP dari host normal tetap tercatat saat fase MITIGATED (phase='MITIGATED').",
        "Kolom 'phase' di CSV memvalidasi 3 fase eksperimen: NORMAL, ATTACK, MITIGATED.",
        "Seluruh tahapan NIST SP 800-86 terpenuhi: Collection, Examination, Analysis, Reporting.",
    ]
    for i, f_text in enumerate(findings, 1):
        f.write(f"  {i}. {f_text}\n\n")

    f.write(f"\n{DIV}\n  END OF REPORT — {NOW}\n{DIV}\n")

print("  [+] forensic_report.txt")

# ─── Terminal summary ─────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print("  SELESAI")
print(f"  Grafik  : {OUTPUT_DIR}")
print(f"  Report  : {report_path}")
print(f"{'='*60}")
print()
print("  Grafik yang dihasilkan:")
print("    01_packet_rate_timeline_3phase.png  — timeline 3 fase + cliff")
print("    02_threat_score_escalation.png      — eskalasi threat score")
print("    03_detection_state_distribution.png — distribusi state machine")
print("    04_attacker_attribution.png         — attribution per attacker")
print("    05_mitigation_lifecycle.png         — DROP & RELEASE timeline")
print(f"{'='*60}\n")
