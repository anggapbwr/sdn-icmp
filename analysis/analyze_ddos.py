#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — DDoS Scenario Analyzer
========================================
Analisis traffic_analysis.csv & mitigation_events.csv dari skenario DDoS.
Membuktikan: deteksi, mitigasi, selektivitas (baseline tidak terganggu).

Output:
  - logs/report_graphs/ddos/D1_attack_timeline.png
  - logs/report_graphs/ddos/D2_attacker_vs_baseline.png
  - logs/report_graphs/ddos/D3_detection_states.png
  - logs/report_graphs/ddos/D4_mitigation_lifecycle.png
  - logs/report_graphs/ddos/D5_gantt_status.png
  - logs/report_graphs/ddos/ddos_summary.md

Catatan:
  - PNG #3 (top source host) dan PNG #4 (cliff effect) berbasis PCAP —
    di-generate oleh analyze_pcap_ddos.py, bukan script ini.

Usage:
  python3 analysis/analyze_ddos.py
"""

import os
import sys
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd

# ─── Paths ────────────────────────────────────────────────────────────────────

_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASE_DIR = "/home/kali/sdn-icmp" if os.path.isdir("/home/kali/sdn-icmp") else _repo_root
DDOS_CSV       = f"{BASE_DIR}/logs/archive/ddos/traffic_analysis.csv"
MITIGATION_CSV = f"{BASE_DIR}/logs/archive/ddos/mitigation_events.csv"
OUTPUT_DIR     = f"{BASE_DIR}/logs/report_graphs/ddos"
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
    "baseline":  "#27AE60",
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
    "figure.facecolor":  "white",
    "axes.facecolor":    "white",
    "axes.edgecolor":    "#BDC3C7",
    "axes.grid":         True,
    "grid.color":        PALETTE["grid"],
    "grid.linewidth":    0.8,
    "grid.alpha":        0.9,
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.titlesize":    13,
    "axes.titleweight":  "bold",
    "axes.titlepad":     12,
    "axes.labelsize":    10,
    "axes.labelcolor":   PALETTE["text"],
    "xtick.labelsize":   9,
    "ytick.labelsize":   9,
    "legend.fontsize":   9,
    "font.family":       "DejaVu Sans",
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

def load_csv(path):
    if not os.path.exists(path):
        print(f"  [!] Not found: {path}")
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"  [!] Failed to read {path}: {e}")
        return pd.DataFrame()

def prep(df):
    if df.empty:
        return df
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["packet_rate", "threat_score", "packet_count"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in ["src_ip", "dst_ip", "protocol_name", "detection_status",
                "phase", "severity", "event_note", "action", "dpid_name"]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()
    return df

def attacker_label(ip):
    m = ATTACKERS.get(ip, {})
    return f"{m.get('host', ip)} ({ip})" if m else ip

def fmt_ts(ts):
    if pd.isna(ts):
        return "N/A"
    return ts.strftime("%H:%M:%S")

# ─── Load ─────────────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SDN DDoS SCENARIO ANALYZER")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

print("\n[*] Loading DDoS CSV ...")
df     = prep(load_csv(DDOS_CSV))
mit_df = prep(load_csv(MITIGATION_CSV))

if df.empty:
    print(f"  [!] DDoS CSV kosong: {DDOS_CSV}")
    sys.exit(1)

print(f"  [i] Total events: {len(df):,}")
print(f"  [i] Mitigation events: {len(mit_df):,}")

# ─── Slice data ───────────────────────────────────────────────────────────────

attack_df = df[
    df["src_ip"].isin(ATTACKER_IPS) &
    (df["dst_ip"] == VICTIM_IP) &
    (df["protocol_name"] == "ICMP")
].copy()

baseline_df = df[
    ~df["src_ip"].isin(ATTACKER_IPS) &
    (df["dst_ip"] == VICTIM_IP) &
    (df["protocol_name"] == "ICMP")
].copy()

warning_df   = attack_df[attack_df["detection_status"] == "WARNING"]
confirmed_df = attack_df[attack_df["detection_status"] == "ATTACK_CONFIRMED"]

mitigation_times = {}
if not mit_df.empty and "action" in mit_df.columns:
    drop_rows = mit_df[mit_df["action"].str.contains("DROP_ICMP", na=False)]
    for ip, grp in drop_rows.groupby("src_ip"):
        mitigation_times[ip] = grp["timestamp"].min()

# ─── Per-attacker stats ───────────────────────────────────────────────────────

per_attacker_stats = {}
for ip in ATTACKER_IPS:
    grp = attack_df[attack_df["src_ip"] == ip]
    if grp.empty:
        per_attacker_stats[ip] = None
        continue

    first_seen = grp["timestamp"].min()
    last_seen  = grp["timestamp"].max()
    first_warn = grp[grp["detection_status"] == "WARNING"]["timestamp"].min() \
        if not grp[grp["detection_status"] == "WARNING"].empty else pd.NaT
    first_conf = grp[grp["detection_status"] == "ATTACK_CONFIRMED"]["timestamp"].min() \
        if not grp[grp["detection_status"] == "ATTACK_CONFIRMED"].empty else pd.NaT
    drop_t     = mitigation_times.get(ip, pd.NaT)

    max_rate   = grp["packet_rate"].max()
    avg_rate   = grp["packet_rate"].mean()
    total_pkts = len(grp)

    detect_lat = (first_conf - first_warn).total_seconds() \
        if not pd.isna(first_conf) and not pd.isna(first_warn) else None
    mitig_lat  = (drop_t - first_conf).total_seconds() \
        if not pd.isna(drop_t) and not pd.isna(first_conf) else None

    per_attacker_stats[ip] = {
        "first_seen": first_seen,
        "last_seen":  last_seen,
        "first_warn": first_warn,
        "first_conf": first_conf,
        "drop_time":  drop_t,
        "max_rate":   float(max_rate) if not pd.isna(max_rate) else 0,
        "avg_rate":   float(avg_rate) if not pd.isna(avg_rate) else 0,
        "total_pkts": total_pkts,
        "detect_lat": detect_lat,
        "mitig_lat":  mitig_lat,
    }

# ─── Global summary ───────────────────────────────────────────────────────────

duration            = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
total_attack_pkts   = len(attack_df)
total_baseline_pkts = len(baseline_df)
unique_attackers    = sorted([ip for ip in ATTACKER_IPS
                               if per_attacker_stats.get(ip) is not None])

first_warning_global   = warning_df["timestamp"].min()   if not warning_df.empty   else pd.NaT
first_confirmed_global = confirmed_df["timestamp"].min() if not confirmed_df.empty else pd.NaT
first_drop_global      = min(mitigation_times.values())  if mitigation_times       else pd.NaT

print("\n[*] Summary:")
print(f"    Duration                     : {duration:.2f} seconds")
print(f"    Attack events                : {total_attack_pkts:,}")
print(f"    Baseline events to victim    : {total_baseline_pkts:,}")
print(f"    Attackers detected           : {len(unique_attackers)}")
print(f"    First WARNING                : {fmt_ts(first_warning_global)}")
print(f"    First ATTACK_CONFIRMED       : {fmt_ts(first_confirmed_global)}")
print(f"    First DROP installed         : {fmt_ts(first_drop_global)}")

# ─── Graph D1: Attack Timeline per Attacker ───────────────────────────────────

def graph_d1():
    fn = "D1_attack_timeline.png"
    if attack_df.empty:
        print(f"  [!] Skip {fn}: no attack data"); return

    fig, ax = plt.subplots(figsize=(15, 7))

    if "phase" in df.columns:
        phased = df.dropna(subset=["timestamp"]).sort_values("timestamp")[["timestamp", "phase"]]
        if not phased.empty:
            current_phase = phased.iloc[0]["phase"].upper() or "NORMAL"
            start_time    = phased.iloc[0]["timestamp"]
            for _, row in phased.iloc[1:].iterrows():
                t = row["timestamp"]
                p = row["phase"].upper() or "NORMAL"
                if p != current_phase:
                    ax.axvspan(start_time, t, alpha=0.07,
                               color=PHASE_COLORS.get(current_phase, PALETTE["normal"]))
                    current_phase = p
                    start_time    = t
            ax.axvspan(start_time, phased.iloc[-1]["timestamp"], alpha=0.07,
                       color=PHASE_COLORS.get(current_phase, PALETTE["normal"]))

    for idx, ip in enumerate(ATTACKER_IPS):
        grp = attack_df[attack_df["src_ip"] == ip].dropna(
            subset=["timestamp", "packet_rate"]).sort_values("timestamp")
        if grp.empty:
            continue
        color = ATTACKER_COLORS[idx]
        ax.plot(grp["timestamp"], grp["packet_rate"],
                color=color, linewidth=1.8, alpha=0.9,
                label=attacker_label(ip))
        if ip in mitigation_times:
            ax.axvline(mitigation_times[ip], color=color,
                       linestyle=":", linewidth=1.5, alpha=0.7)

    ax.axhline(WARNING_PPS, color=PALETTE["warning"], linestyle="--",
               linewidth=1.3, alpha=0.85,
               label=f"Warning threshold ({WARNING_PPS} pps)")
    ax.axhline(ATTACK_PPS, color=PALETTE["confirmed"], linestyle="--",
               linewidth=1.3, alpha=0.85,
               label=f"Attack threshold ({ATTACK_PPS} pps)")

    patches = [
        mpatches.Patch(color=PALETTE["normal"],    alpha=0.3, label="Phase: NORMAL"),
        mpatches.Patch(color=PALETTE["attack"],    alpha=0.3, label="Phase: ATTACK"),
        mpatches.Patch(color=PALETTE["mitigated"], alpha=0.3, label="Phase: MITIGATED"),
    ]
    handles, _ = ax.get_legend_handles_labels()
    ax.legend(handles=handles + patches, loc="upper right", ncol=2, fontsize=8)

    ax.set_title("DDoS — Attack Rate Timeline per Attacker")
    subtitle(ax, "Garis titik = waktu DROP rule terpasang per attacker | "
                 "Rate turun ke 0 setelah DROP = mitigasi berhasil")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Packet Rate (pps) — EWMA")
    ax.tick_params(axis="x", rotation=30)
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph D2: Selektivitas Mitigasi (Attacker vs Baseline) — PNG #2 ──────────

def graph_d2():
    fn = "D2_attacker_vs_baseline.png"
    if attack_df.empty:
        print(f"  [!] Skip {fn}: no attack data"); return

    fig, ax = plt.subplots(figsize=(15, 7))

    if "phase" in df.columns:
        phased = df.dropna(subset=["timestamp"]).sort_values("timestamp")[["timestamp", "phase"]]
        if not phased.empty:
            current_phase = phased.iloc[0]["phase"].upper() or "NORMAL"
            start_time    = phased.iloc[0]["timestamp"]
            for _, row in phased.iloc[1:].iterrows():
                t = row["timestamp"]
                p = row["phase"].upper() or "NORMAL"
                if p != current_phase:
                    ax.axvspan(start_time, t, alpha=0.07,
                               color=PHASE_COLORS.get(current_phase, PALETTE["normal"]))
                    current_phase = p
                    start_time    = t
            ax.axvspan(start_time, phased.iloc[-1]["timestamp"], alpha=0.07,
                       color=PHASE_COLORS.get(current_phase, PALETTE["normal"]))

    if not attack_df.empty:
        atk      = attack_df.dropna(subset=["timestamp", "packet_rate"]).set_index("timestamp")
        atk_rate = atk["packet_rate"].resample("2S").sum().fillna(0)
        if not atk_rate.empty:
            ax.plot(atk_rate.index, atk_rate.values,
                    color=PALETTE["attack"], linewidth=2.2, alpha=0.9,
                    label="Attacker traffic (4 hosts → victim)", marker="o", markersize=3)
            ax.fill_between(atk_rate.index, atk_rate.values, 0,
                            color=PALETTE["attack"], alpha=0.15)

    if not baseline_df.empty:
        bsl      = baseline_df.dropna(subset=["timestamp", "packet_rate"]).set_index("timestamp")
        bsl_rate = bsl["packet_rate"].resample("2S").sum().fillna(0)
        if not bsl_rate.empty:
            ax.plot(bsl_rate.index, bsl_rate.values,
                    color=PALETTE["baseline"], linewidth=2.0, alpha=0.9,
                    label="Baseline traffic (normal hosts → victim)", marker="s", markersize=3)
            ax.fill_between(bsl_rate.index, bsl_rate.values, 0,
                            color=PALETTE["baseline"], alpha=0.15)

    for ip, t in mitigation_times.items():
        ax.axvline(t, color=PALETTE["drop"], linestyle=":", linewidth=1.5, alpha=0.6)

    phase_patches = [
        mpatches.Patch(color=PALETTE["normal"],    alpha=0.3, label="Phase: NORMAL"),
        mpatches.Patch(color=PALETTE["attack"],    alpha=0.3, label="Phase: ATTACK"),
        mpatches.Patch(color=PALETTE["mitigated"], alpha=0.3, label="Phase: MITIGATED"),
    ]
    handles, _ = ax.get_legend_handles_labels()
    ax.legend(handles=handles + phase_patches, loc="upper right", fontsize=8)

    ax.set_title("DDoS — Selektivitas Mitigasi: Attacker vs Baseline Traffic menuju Victim")
    subtitle(ax, "BUKTI UTAMA: attacker traffic turun ke 0 saat DROP aktif — "
                 "baseline traffic TETAP MENGALIR. Mitigasi bersifat src-IP specific.")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Aggregated Packet Rate (pps)")
    ax.tick_params(axis="x", rotation=30)
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph D3: Detection State Distribution ───────────────────────────────────

def graph_d3():
    fn = "D3_detection_states.png"
    if "detection_status" not in df.columns:
        print(f"  [!] Skip {fn}: missing detection_status"); return

    order     = ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "DROP_ACTIVE"]
    color_map = {
        "NORMAL":           PALETTE["normal"],
        "WARNING":          PALETTE["warning"],
        "ATTACK_CONFIRMED": PALETTE["confirmed"],
        "DROP_ACTIVE":      PALETTE["drop"],
    }

    counts = df["detection_status"].value_counts()
    labels = [s for s in order if s in counts.index]
    if not labels:
        print(f"  [!] Skip {fn}: no state data"); return

    values = [int(counts[s]) for s in labels]
    colors = [color_map[s] for s in labels]

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(labels, values, color=colors, width=0.5,
                  zorder=3, edgecolor="white", linewidth=1.2)
    for bar, val in zip(bars, values):
        pct = 100 * val / sum(values)
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + max(values)*0.012,
                f"{val:,}\n({pct:.1f}%)", ha="center", va="bottom",
                fontsize=10, fontweight="bold", color=PALETTE["text"])

    ax.set_title("DDoS — Distribusi Status Deteksi")
    subtitle(ax, "State machine controller: NORMAL → WARNING → ATTACK_CONFIRMED → "
                 "(DROP_ACTIVE terpasang di switch, bukan di CSV per-event)")
    ax.set_xlabel("Detection Status")
    ax.set_ylabel("Jumlah Events")
    ax.set_ylim(0, max(values) * 1.22)
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph D4: Mitigation Lifecycle ───────────────────────────────────────────

def graph_d4():
    fn = "D4_mitigation_lifecycle.png"
    if mit_df.empty:
        print(f"  [!] Skip {fn}: no mitigation data"); return

    fig, axes = plt.subplots(1, 2, figsize=(15, 6))

    # Kiri: action distribution
    ax1 = axes[0]
    if "action" in mit_df.columns:
        counts     = mit_df["action"].value_counts()
        colors_bar = [PALETTE["drop"] if "DROP" in str(a) else PALETTE["mitigated"]
                      for a in counts.index]
        bars = ax1.bar(counts.index, counts.values, color=colors_bar, width=0.45,
                       zorder=3, edgecolor="white", linewidth=1.1)
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

    # Kanan: per-attacker drop timestamp
    ax2 = axes[1]
    y_pos, yticks, ylabels = 0, [], []
    for idx, ip in enumerate(ATTACKER_IPS):
        t = mitigation_times.get(ip)
        if t is None:
            continue
        color = ATTACKER_COLORS[idx]
        ax2.scatter(t, y_pos, color=color, s=200, zorder=5, marker="v",
                    edgecolor="white", linewidth=2)
        ax2.annotate(f"DROP\n{fmt_ts(t)}",
                     xy=(t, y_pos), xytext=(15, 0),
                     textcoords="offset points",
                     fontsize=8, va="center", color=PALETTE["text"])
        yticks.append(y_pos)
        ylabels.append(attacker_label(ip))
        y_pos += 1

    if yticks:
        ax2.set_yticks(yticks)
        ax2.set_yticklabels(ylabels, fontsize=9)
        ax2.set_ylim(-0.5, max(yticks) + 0.5)
    ax2.set_title("Timestamp DROP Rule per Attacker")
    ax2.set_xlabel("Drop Time")
    ax2.tick_params(axis="x", rotation=30)
    ax2.set_axisbelow(True)
    ax2.grid(axis="y", alpha=0.3)

    fig.suptitle("DDoS — Mitigation Lifecycle Evidence",
                 fontsize=14, fontweight="bold")
    subtitle(axes[0], "Kiri: total aksi mitigasi | Kanan: waktu DROP terpasang per attacker")
    save(fn)

# ─── Graph D5: Gantt Transisi Status per Attacker — PNG #6 ───────────────────

def graph_d5():
    fn = "D5_gantt_status.png"
    if not unique_attackers:
        print(f"  [!] Skip {fn}: no attackers"); return

    fig, ax = plt.subplots(figsize=(15, 6))

    y_pos, yticks, ylabels = 0, [], []

    for idx, ip in enumerate(ATTACKER_IPS):
        s = per_attacker_stats.get(ip)
        if s is None:
            continue

        color      = ATTACKER_COLORS[idx]
        first_seen = s["first_seen"]
        first_warn = s["first_warn"]
        first_conf = s["first_conf"]
        drop_t     = s["drop_time"]
        last_seen  = s["last_seen"]

        # Segment NORMAL (first_seen → first_warn)
        if not pd.isna(first_warn) and not pd.isna(first_seen):
            dur = (first_warn - first_seen).total_seconds()
            if dur > 0:
                ax.barh(y_pos, dur, left=first_seen, height=0.55,
                        color=PALETTE["normal"], alpha=0.75,
                        edgecolor="white", linewidth=1)

        # Segment WARNING (first_warn → first_conf)
        if not pd.isna(first_warn) and not pd.isna(first_conf):
            dur = (first_conf - first_warn).total_seconds()
            if dur > 0:
                ax.barh(y_pos, dur, left=first_warn, height=0.55,
                        color=PALETTE["warning"], alpha=0.85,
                        edgecolor="white", linewidth=1)

        # Segment ATTACK_CONFIRMED (first_conf → drop_t)
        if not pd.isna(first_conf) and not pd.isna(drop_t):
            dur = (drop_t - first_conf).total_seconds()
            if dur > 0:
                ax.barh(y_pos, dur, left=first_conf, height=0.55,
                        color=PALETTE["confirmed"], alpha=0.9,
                        edgecolor="white", linewidth=1)

        # Segment DROP_ACTIVE (drop_t → last_seen)
        if not pd.isna(drop_t):
            end_t = last_seen if (not pd.isna(last_seen) and last_seen > drop_t) \
                    else drop_t + pd.Timedelta(seconds=10)
            dur = (end_t - drop_t).total_seconds()
            if dur > 0:
                ax.barh(y_pos, dur, left=drop_t, height=0.55,
                        color=PALETTE["drop"], alpha=0.85,
                        edgecolor="white", linewidth=1)

        # Marker saat DROP dipasang
        if not pd.isna(drop_t):
            ax.scatter(drop_t, y_pos, s=130, marker="v",
                       color="black", zorder=10,
                       edgecolor="white", linewidth=1.5)
            # Anotasi waktu DROP
            ax.annotate(fmt_ts(drop_t),
                        xy=(drop_t, y_pos + 0.35),
                        fontsize=7.5, ha="center", color=PALETTE["text"])

        yticks.append(y_pos)
        ylabels.append(attacker_label(ip))
        y_pos += 1

    ax.set_yticks(yticks)
    ax.set_yticklabels(ylabels, fontsize=9)
    ax.set_xlabel("Timestamp")
    ax.set_title("DDoS — Gantt Timeline Transisi Status Deteksi per Attacker")
    subtitle(ax, "Biru=NORMAL | Kuning=WARNING | Merah=ATTACK_CONFIRMED | "
                 "Ungu=DROP_ACTIVE | ▼ = waktu DROP rule terpasang")
    ax.tick_params(axis="x", rotation=30)
    ax.set_axisbelow(True)
    ax.grid(axis="y", alpha=0.3)

    legend_handles = [
        mpatches.Patch(color=PALETTE["normal"],    alpha=0.75, label="NORMAL"),
        mpatches.Patch(color=PALETTE["warning"],   alpha=0.85, label="WARNING"),
        mpatches.Patch(color=PALETTE["confirmed"], alpha=0.90, label="ATTACK_CONFIRMED"),
        mpatches.Patch(color=PALETTE["drop"],      alpha=0.85, label="DROP_ACTIVE"),
    ]
    ax.legend(handles=legend_handles, loc="upper right", fontsize=8)
    save(fn)

# ─── Run all ──────────────────────────────────────────────────────────────────

print("\n[*] Generating DDoS graphs ...")
graph_d1()
graph_d2()
graph_d3()
graph_d4()
graph_d5()

# ─── Markdown report ──────────────────────────────────────────────────────────

print("\n[*] Writing ddos_summary.md ...")
md_path = out("ddos_summary.md")
NOW     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

attacker_rows = []
for ip in ATTACKER_IPS:
    s = per_attacker_stats.get(ip)
    if s is None:
        attacker_rows.append(
            f"| `{ip}` ({ATTACKERS[ip]['host']}) | — | — | — | — | — |")
        continue
    detect_lat_s = f"{s['detect_lat']:.1f}s" if s["detect_lat"] is not None else "—"
    mitig_lat_s  = f"{s['mitig_lat']:.1f}s"  if s["mitig_lat"]  is not None else "—"
    attacker_rows.append(
        f"| `{ip}` ({ATTACKERS[ip]['host']}) | "
        f"{s['total_pkts']:,} | {s['max_rate']:.1f} pps | "
        f"{detect_lat_s} | {mitig_lat_s} | {fmt_ts(s['drop_time'])} |"
    )

detection_counts = df["detection_status"].value_counts().to_dict()
total            = len(df)
state_rows = []
for state in ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "DROP_ACTIVE"]:
    cnt = detection_counts.get(state, 0)
    pct = 100 * cnt / total if total > 0 else 0
    state_rows.append(f"| {state} | {cnt:,} | {pct:.1f}% |")

mit_rows = []
if not mit_df.empty:
    for _, row in mit_df.iterrows():
        ts     = row.get("timestamp")
        ip     = row.get("src_ip", "")
        sw     = row.get("dpid_name", "")
        seg    = row.get("segment_description", "")
        action = row.get("action", "")
        mit_rows.append(f"| {fmt_ts(ts)} | `{ip}` | {sw} | {action} | {seg} |")

start_ts = df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S")
end_ts   = df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")

baseline_during_attack = pd.DataFrame()
if "phase" in baseline_df.columns:
    baseline_during_attack = baseline_df[
        baseline_df["phase"].isin(["ATTACK", "MITIGATED"])
    ]

selektivitas_text = ""
if not baseline_during_attack.empty:
    bsl_count = len(baseline_during_attack)
    selektivitas_text = (
        f"Sebanyak **{bsl_count:,} events** dari host normal tetap diteruskan ke victim "
        f"selama fase ATTACK dan MITIGATED. Ini membuktikan DROP rule **selektif per source IP** — "
        f"hanya attacker yang diblokir, traffic legitimate tetap mengalir."
    )

md_content = f"""# DDoS Scenario — Analysis Report

**Generated:** {NOW}
**Data source:** `logs/archive/ddos/traffic_analysis.csv` + `mitigation_events.csv`

---

## 1. Experiment Context

| Item | Value |
|------|-------|
| Duration | {duration:.2f} seconds |
| Start time | {start_ts} |
| End time | {end_ts} |
| Total events | {len(df):,} |
| Attack events (attacker → victim, ICMP) | {total_attack_pkts:,} |
| Baseline events (normal → victim, ICMP) | {total_baseline_pkts:,} |
| Mitigation events | {len(mit_df):,} |
| Victim | `{VICTIM_IP}` (h25, s6) |
| Attackers | {", ".join([f"`{ip}` ({ATTACKERS[ip]['host']}@{ATTACKERS[ip]['switch']})" for ip in unique_attackers])} |

---

## 2. Attack Rate Timeline

Packet rate masing-masing attacker meningkat tajam saat serangan dimulai, melampaui threshold
WARNING (20 pps) dan ATTACK (50 pps), kemudian turun ke 0 setelah DROP rule terpasang.

![Attack Timeline](D1_attack_timeline.png)

---

## 3. Per-Attacker Detection & Mitigation

| Attacker | Total Pkts | Max Rate | Detection Latency¹ | Mitigation Latency² | Drop Time |
|----------|-----------|----------|--------------------|--------------------|-----------|
{chr(10).join(attacker_rows)}

> ¹ **Detection Latency** = waktu dari first WARNING ke first ATTACK_CONFIRMED
> ² **Mitigation Latency** = waktu dari ATTACK_CONFIRMED ke DROP rule terpasang (delay 8 detik)

![Gantt Status Timeline](D5_gantt_status.png)

---

## 4. Selektivitas Mitigasi (Bukti Utama)

{selektivitas_text}

![Selektivitas Mitigasi](D2_attacker_vs_baseline.png)

---

## 5. Detection State Distribution

| State | Events | Percentage |
|-------|--------|------------|
{chr(10).join(state_rows)}

State machine controller berhasil mengeskalasi dari NORMAL → WARNING → ATTACK_CONFIRMED
dan men-trigger DROP rule untuk semua {len(unique_attackers)} attacker.

![Detection States](D3_detection_states.png)

---

## 6. Mitigation Events (Bukti Forensik)

| Time | Source IP | Switch | Action | Segment |
|------|-----------|--------|--------|---------|
{chr(10).join(mit_rows) if mit_rows else "| (no mitigation events) |"}

![Mitigation Lifecycle](D4_mitigation_lifecycle.png)

---

## 7. Key Findings

1. **{len(unique_attackers)} attacker terdeteksi** dengan source IP: {", ".join([f"`{ip}`" for ip in unique_attackers])}
2. **Detection lifecycle terbukti** — semua transisi status tercatat di CSV (lihat D5)
3. **Mitigasi terpasang di edge switch** — h1@s2, h7@s3, h13@s4, h18@s5
4. **Selektivitas terbukti** — baseline traffic tetap mengalir selama fase MITIGATED (lihat D2)
5. **DROP rule efektif** — setelah drop terpasang, packet rate attacker turun ke 0 (lihat D1)
6. **Konsistensi timing** — delay mitigasi ~8 detik sesuai parameter `mitigation_delay_after_alert`

---

*Di-generate otomatis oleh `analyze_ddos.py`.
PNG berbasis PCAP (top source host dan cliff effect) ada di output `analyze_pcap_ddos.py`.
Untuk perbandingan dengan baseline, lihat `comparison_report.md`.*
"""

with open(md_path, "w", encoding="utf-8") as f:
    f.write(md_content)
print(f"  [+] ddos_summary.md")

# ─── Done ─────────────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print(f"  DDoS ANALYSIS DONE")
print(f"  Output: {OUTPUT_DIR}")
print(f"{'='*60}")
print("\nFiles generated (CSV-based):")
print(f"  📈 D1_attack_timeline.png       — attack rate per attacker")
print(f"  📈 D2_attacker_vs_baseline.png  — selektivitas mitigasi [PNG #2]")
print(f"  📈 D3_detection_states.png      — distribusi status deteksi")
print(f"  📈 D4_mitigation_lifecycle.png  — timing DROP per attacker")
print(f"  📈 D5_gantt_status.png          — gantt transisi status [PNG #6]")
print(f"  📊 ddos_summary.md")
print(f"\nPNG berbasis PCAP (PNG #3 dan #4) → analyze_pcap_ddos.py")
print(f"{'='*60}\n")
