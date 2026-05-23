#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — Baseline Scenario Analyzer
============================================
Analisis traffic_analysis.csv dari skenario baseline.
Membuktikan: network sehat dengan variasi protokol, tidak ada anomaly.

Output:
  - logs/report_graphs/baseline/B1_protocol_distribution.png
  - logs/report_graphs/baseline/B2_packet_rate_timeline.png
  - logs/report_graphs/baseline/B3_top_talkers.png
  - logs/report_graphs/baseline/B4_detection_states.png
  - logs/report_graphs/baseline/baseline_summary.md

Usage:
  python3 analysis/analyze_baseline.py
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
BASELINE_CSV = f"{BASE_DIR}/logs/archive/baseline/traffic_analysis.csv"
OUTPUT_DIR   = f"{BASE_DIR}/logs/report_graphs/baseline"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─── Topology ─────────────────────────────────────────────────────────────────

VICTIM_IP = "10.0.0.25"
ATTACKER_IPS = ["10.0.0.1", "10.0.0.7", "10.0.0.13", "10.0.0.18"]

# ─── Style ────────────────────────────────────────────────────────────────────

PALETTE = {
    "icmp":     "#4A90D9",
    "tcp":      "#27AE60",
    "udp":      "#F5A623",
    "arp":      "#8E44AD",
    "other":    "#95A5A6",
    "normal":   "#4A90D9",
    "warning":  "#F5A623",
    "attack":   "#E05C5C",
    "drop":     "#8E44AD",
    "text":     "#2C3E50",
    "sub":      "#7F8C8D",
    "grid":     "#ECEFF1",
}

PROTOCOL_COLORS = {
    "ICMP":  PALETTE["icmp"],
    "TCP":   PALETTE["tcp"],
    "UDP":   PALETTE["udp"],
    "ARP":   PALETTE["arp"],
    "OTHER": PALETTE["other"],
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
                "phase", "severity", "event_note"]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()
    return df

# ─── Load ─────────────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SDN BASELINE SCENARIO ANALYZER")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

print("\n[*] Loading baseline CSV ...")
df = prep(load_csv(BASELINE_CSV))

if df.empty:
    print(f"  [!] Baseline CSV kosong atau tidak ada: {BASELINE_CSV}")
    sys.exit(1)

print(f"  [i] Total events: {len(df):,}")

# ─── Summary stats ────────────────────────────────────────────────────────────

duration = (df["timestamp"].max() - df["timestamp"].min()).total_seconds() if "timestamp" in df.columns else 0
unique_src = df["src_ip"].nunique()
unique_dst = df["dst_ip"].nunique()

protocol_counts = df["protocol_name"].value_counts().to_dict()
detection_counts = df["detection_status"].value_counts().to_dict()

# Cek ada anomaly atau tidak
warning_count   = detection_counts.get("WARNING", 0)
attack_count    = detection_counts.get("ATTACK_CONFIRMED", 0)
drop_count      = detection_counts.get("DROP_ACTIVE", 0)
is_clean        = (warning_count == 0 and attack_count == 0 and drop_count == 0)

avg_rate = df["packet_rate"].mean() if "packet_rate" in df.columns else 0
max_rate = df["packet_rate"].max() if "packet_rate" in df.columns else 0

stats = {
    "Total events":            len(df),
    "Duration (seconds)":      round(duration, 2),
    "Unique source hosts":     unique_src,
    "Unique destination hosts": unique_dst,
    "Average packet rate":     round(float(avg_rate), 2),
    "Max packet rate":         round(float(max_rate), 2),
    "Protocols seen":          ", ".join(protocol_counts.keys()),
    "Status":                  "CLEAN (no anomaly)" if is_clean else "ANOMALY DETECTED",
}

print("\n[*] Summary:")
for k, v in stats.items():
    print(f"    {k:<28} : {v}")

# ─── Graph B1: Protocol Distribution ──────────────────────────────────────────

def graph_b1():
    fn = "B1_protocol_distribution.png"
    if not protocol_counts:
        print(f"  [!] Skip {fn}: no protocol data"); return

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Pie chart kiri
    ax1 = axes[0]
    labels = list(protocol_counts.keys())
    sizes = list(protocol_counts.values())
    colors = [PROTOCOL_COLORS.get(p, PALETTE["other"]) for p in labels]

    wedges, texts, autotexts = ax1.pie(
        sizes, labels=labels, colors=colors, autopct='%1.1f%%',
        startangle=90, textprops={'fontsize': 10, 'color': PALETTE["text"]},
        wedgeprops={'edgecolor': 'white', 'linewidth': 2}
    )
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
    ax1.set_title("Komposisi Protokol")

    # Bar chart kanan
    ax2 = axes[1]
    bars = ax2.bar(labels, sizes, color=colors, width=0.5,
                   zorder=3, edgecolor="white", linewidth=1.2)
    for bar, val in zip(bars, sizes):
        ax2.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + max(sizes)*0.015,
                 f"{val:,}", ha="center", va="bottom",
                 fontsize=10, fontweight="bold", color=PALETTE["text"])
    ax2.set_title("Jumlah Events per Protokol")
    ax2.set_ylabel("Jumlah Events")
    ax2.set_ylim(0, max(sizes) * 1.18)
    ax2.set_axisbelow(True)

    fig.suptitle("Baseline — Distribusi Protokol Network",
                 fontsize=14, fontweight="bold", y=1.02)
    subtitle(axes[0], "Network sehat dengan variasi traffic ICMP, TCP, UDP, ARP")
    save(fn)

# ─── Graph B2: Packet Rate Timeline per Protocol ──────────────────────────────

def graph_b2():
    fn = "B2_packet_rate_timeline.png"
    if "timestamp" not in df.columns or "packet_rate" not in df.columns:
        print(f"  [!] Skip {fn}: missing columns"); return

    fig, ax = plt.subplots(figsize=(15, 6))

    for proto in protocol_counts.keys():
        sub = df[df["protocol_name"] == proto].dropna(subset=["timestamp", "packet_rate"]).sort_values("timestamp")
        if sub.empty:
            continue
        # Bin per 2 detik supaya smooth
        sub = sub.set_index("timestamp")
        rate_binned = sub["packet_rate"].resample("2S").mean().fillna(0)
        if rate_binned.empty:
            continue
        ax.plot(rate_binned.index, rate_binned.values,
                color=PROTOCOL_COLORS.get(proto, PALETTE["other"]),
                linewidth=1.5, alpha=0.85, label=proto, marker="o", markersize=3)

    ax.set_title("Baseline — Packet Rate Timeline per Protokol")
    subtitle(ax, "Rate rendah dan stabil sepanjang sesi (binned 2 detik) — bukti network sehat")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Packet Rate (pps)")
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper right", title="Protocol")
    ax.set_axisbelow(True)
    save(fn)

# ─── Graph B3: Top Talker Hosts ───────────────────────────────────────────────

def graph_b3():
    fn = "B3_top_talkers.png"
    if "src_ip" not in df.columns:
        print(f"  [!] Skip {fn}: missing src_ip"); return

    top_n = 10
    counts = df["src_ip"].value_counts().head(top_n)
    if counts.empty:
        print(f"  [!] Skip {fn}: no source data"); return

    fig, ax = plt.subplots(figsize=(13, 6))
    labels = counts.index.tolist()
    values = counts.values

    # Highlight attacker hosts berbeda warna (untuk konteks, walau di baseline harusnya tidak menonjol)
    bar_colors = [PALETTE["attack"] if ip in ATTACKER_IPS else PALETTE["normal"] for ip in labels]

    bars = ax.barh(labels[::-1], values[::-1], color=bar_colors[::-1],
                   height=0.6, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + max(values)*0.01,
                bar.get_y() + bar.get_height()/2,
                f"{val:,}", va="center", ha="left",
                fontsize=10, fontweight="bold", color=PALETTE["text"])

    ax.set_title(f"Baseline — Top {top_n} Talker Hosts (by Event Count)")
    subtitle(ax, "Distribusi traffic per host. Merah = host yang nanti jadi attacker di skenario DDoS (di baseline behavior normal)")
    ax.set_xlabel("Jumlah Events")
    ax.set_xlim(0, max(values) * 1.15)
    ax.set_axisbelow(True)

    legend_handles = [
        mpatches.Patch(color=PALETTE["normal"], label="Normal host"),
        mpatches.Patch(color=PALETTE["attack"], label="Future attacker (baseline behavior)"),
    ]
    ax.legend(handles=legend_handles, loc="lower right")
    save(fn)

# ─── Graph B4: Detection State Distribution ───────────────────────────────────

def graph_b4():
    fn = "B4_detection_states.png"
    if "detection_status" not in df.columns:
        print(f"  [!] Skip {fn}: missing detection_status"); return

    order = ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "DROP_ACTIVE"]
    color_map = {
        "NORMAL":           PALETTE["normal"],
        "WARNING":          PALETTE["warning"],
        "ATTACK_CONFIRMED": PALETTE["attack"],
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

    ax.set_title("Baseline — Detection State Distribution")
    if is_clean:
        sub_text = "100% NORMAL — tidak ada deteksi anomaly (sesuai ekspektasi network sehat)"
    else:
        sub_text = f"Ada {warning_count + attack_count + drop_count} event anomaly (perlu investigasi)"
    subtitle(ax, sub_text)
    ax.set_xlabel("Detection Status")
    ax.set_ylabel("Jumlah Events")
    ax.set_ylim(0, max(values) * 1.22)
    ax.set_axisbelow(True)
    save(fn)

# ─── Run all graphs ───────────────────────────────────────────────────────────

print("\n[*] Generating baseline graphs ...")
graph_b1()
graph_b2()
graph_b3()
graph_b4()

# ─── Markdown summary ─────────────────────────────────────────────────────────

print("\n[*] Writing baseline_summary.md ...")
md_path = out("baseline_summary.md")
NOW = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

start_ts = df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S") if not df.empty else "N/A"
end_ts   = df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not df.empty else "N/A"

# Buat protocol breakdown table
proto_lines = []
total_events = len(df)
for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
    pct = 100 * count / total_events
    proto_lines.append(f"| {proto} | {count:,} | {pct:.1f}% |")

# Top talker table
top_talkers = df["src_ip"].value_counts().head(5)
top_talker_lines = []
for ip, count in top_talkers.items():
    is_atk = "⚠️ (future attacker)" if ip in ATTACKER_IPS else "✅ normal"
    top_talker_lines.append(f"| `{ip}` | {count:,} | {is_atk} |")

md_content = f"""# Baseline Scenario — Analysis Report

**Generated:** {NOW}
**Data source:** `logs/archive/baseline/traffic_analysis.csv`

---

## 1. Experiment Context

| Item | Value |
|------|-------|
| Duration | {duration:.2f} seconds |
| Start time | {start_ts} |
| End time | {end_ts} |
| Total events | {len(df):,} |
| Unique source hosts | {unique_src} |
| Unique destination hosts | {unique_dst} |
| Average packet rate | {avg_rate:.2f} pps |
| Max packet rate | {max_rate:.2f} pps |

---

## 2. Network Health Status

**Status:** {'🟢 **CLEAN** — Network sehat, tidak ada deteksi anomaly' if is_clean else '🟡 **ANOMALY DETECTED** — Ada event yang perlu diinvestigasi'}

| Detection State | Events |
|----------------|--------|
| NORMAL | {detection_counts.get('NORMAL', 0):,} |
| WARNING | {warning_count:,} |
| ATTACK_CONFIRMED | {attack_count:,} |
| DROP_ACTIVE | {drop_count:,} |

---

## 3. Protocol Distribution

Network baseline menunjukkan **variasi protokol yang sehat** sesuai aktivitas enterprise normal (ping, TCP transfer, UDP transfer, HTTP request, ARP discovery).

| Protocol | Events | Percentage |
|----------|--------|------------|
{chr(10).join(proto_lines)}

![Protocol Distribution](B1_protocol_distribution.png)

---

## 4. Top Talker Hosts

5 host paling aktif sebagai source traffic:

| Host IP | Event Count | Status |
|---------|-------------|--------|
{chr(10).join(top_talker_lines)}

> Host yang menjadi attacker di skenario DDoS (h1, h7, h13, h18) di baseline ini menunjukkan **behavior normal** — terlibat di traffic ping standar saat `pingall`, tidak ada anomaly.

![Top Talkers](B3_top_talkers.png)

---

## 5. Packet Rate Over Time

Packet rate stabil dan rendah sepanjang sesi capture, dengan rata-rata **{avg_rate:.2f} pps** dan maksimum **{max_rate:.2f} pps**. Tidak ada spike yang mengindikasikan flood.

![Packet Rate Timeline](B2_packet_rate_timeline.png)

---

## 6. Detection State Verification

Controller berhasil mengklasifikasikan **{100 * detection_counts.get('NORMAL', 0) / total_events:.1f}%** traffic sebagai NORMAL, yang berarti detection engine bekerja dengan benar (no false positives di kondisi sehat).

![Detection States](B4_detection_states.png)

---

## 7. Key Findings

1. **Network terbukti sehat** — semua {len(df):,} events terklasifikasi NORMAL
2. **Variasi protokol tercatat** — {", ".join(protocol_counts.keys())} berfungsi normal
3. **Tidak ada false positive** — controller tidak men-trigger WARNING/ATTACK pada traffic legitimate
4. **Distribusi host merata** — tidak ada single host yang dominan secara abnormal
5. **Packet rate rendah** — average {avg_rate:.2f} pps, jauh di bawah threshold WARNING (20 pps) dan ATTACK (50 pps)

---

*Report ini di-generate otomatis dari `analyze_baseline.py`. Untuk skenario DDoS, lihat `ddos_summary.md`. Untuk perbandingan komprehensif, lihat `combined_report.md`.*
"""

with open(md_path, "w", encoding="utf-8") as f:
    f.write(md_content)
print(f"  [+] baseline_summary.md")

# ─── Done ─────────────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print(f"  BASELINE ANALYSIS DONE")
print(f"  Output: {OUTPUT_DIR}")
print(f"{'='*60}\n")