#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — PCAP Forensic Analyzer (Gabungan 3 Skenario)
================================================================
Membaca pcap dari 3 skenario: baseline, ddos_unmitigated, ddos (raw+clean).
Menggantikan analyze_pcap_baseline.py, analyze_pcap_ddos.py, dan bagian
PCAP dari analyze_combined.py.

Output:
  - logs/report_graphs/pcap/G5_top_source_host.png
  - logs/report_graphs/pcap/G6_cliff_effect_raw_vs_clean.png
  - logs/report_graphs/pcap/G7_throughput_performance.png
  - logs/report_graphs/pcap/pcap_summary.md

Usage:
  python3 analysis/analyze_pcap.py
"""

import os
import sys
import subprocess
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

PCAP_FILES = {
    "baseline":         f"{BASE_DIR}/logs/archive/baseline/network_baseline.pcap",
    "ddos_unmitigated": f"{BASE_DIR}/logs/archive/ddos_unmitigated/network_ddos_unmitigated.pcap",
    "ddos_raw":         f"{BASE_DIR}/logs/archive/ddos/network_ddos.pcap",
    "ddos_clean":       f"{BASE_DIR}/logs/archive/ddos/network_ddos_clean.pcap",
}
MITIGATION_CSV = f"{BASE_DIR}/logs/archive/ddos/mitigation_events.csv"
OUTPUT_DIR     = f"{BASE_DIR}/logs/report_graphs/pcap"
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

# ─── Style ────────────────────────────────────────────────────────────────────

PALETTE = {
    "icmp":     "#4A90D9",
    "tcp":      "#27AE60",
    "arp":      "#8E44AD",
    "other":    "#95A5A6",
    "attack":   "#E05C5C",
    "normal":   "#4A90D9",
    "baseline": "#27AE60",
    "drop":     "#8E44AD",
    "unmit":    "#E05C5C",
    "mit":      "#27AE60",
    "text":     "#2C3E50",
    "sub":      "#7F8C8D",
    "grid":     "#ECEFF1",
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

def check_tshark():
    try:
        result = subprocess.run(["tshark", "-v"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def tshark_extract(pcap, fields):
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=|", "-E", "occurrence=f"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"  [!] tshark error: {result.stderr[:200]}")
            return []
    except subprocess.TimeoutExpired:
        print(f"  [!] tshark timeout (>600s)")
        return []
    rows = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|")
        if len(parts) != len(fields):
            continue
        rows.append(dict(zip(fields, parts)))
    return rows

def classify_protocol(row):
    if row.get("arp.opcode"):
        return "ARP"
    proto_num = row.get("ip.proto", "")
    if proto_num == "1":  return "ICMP"
    if proto_num == "6":  return "TCP"
    if proto_num == "17": return "UDP"
    return "OTHER"

def ip_to_host(ip):
    if not ip or "." not in ip:
        return "unknown"
    try:
        return f"h{int(ip.split('.')[-1])}"
    except (ValueError, IndexError):
        return ip

def attacker_label(ip):
    m = ATTACKERS.get(ip, {})
    return f"{m.get('host', ip)} ({ip})" if m else ip

def load_pcap(path, label):
    if not os.path.exists(path):
        print(f"  [!] PCAP not found ({label}): {path}")
        return pd.DataFrame()
    size_mb = os.path.getsize(path) / 1024 / 1024
    print(f"\n[*] Loading {label}: {os.path.basename(path)} ({size_mb:.2f} MB)")
    fields = [
        "frame.time_epoch", "frame.len",
        "ip.src", "ip.dst", "ip.proto",
        "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport",
        "icmp.type",
    ]
    rows = tshark_extract(path, fields)
    print(f"  [i] Extracted {len(rows):,} packets")
    if not rows:
        return pd.DataFrame()

    records = []
    for r in rows:
        proto = classify_protocol(r)
        src   = r.get("ip.src") or r.get("arp.src.proto_ipv4") or ""
        dst   = r.get("ip.dst") or r.get("arp.dst.proto_ipv4") or ""
        try:
            ts = float(r.get("frame.time_epoch", "0"))
        except (ValueError, TypeError):
            ts = 0
        try:
            size = int(r.get("frame.len", "0"))
        except (ValueError, TypeError):
            size = 0
        records.append({"timestamp": ts, "size": size,
                        "src": src, "dst": dst, "protocol": proto})

    df = pd.DataFrame(records)
    df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
    return df

# ─── Main load ─────────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SDN PCAP FORENSIC ANALYZER — 3 SKENARIO")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

if not check_tshark():
    print("  [!] tshark tidak terpasang. Install: sudo apt install -y tshark")
    sys.exit(1)

df_baseline = load_pcap(PCAP_FILES["baseline"], "Baseline")
df_unmit    = load_pcap(PCAP_FILES["ddos_unmitigated"], "DDoS Unmitigated")
df_raw      = load_pcap(PCAP_FILES["ddos_raw"], "DDoS Raw (mitigated)")
df_clean    = load_pcap(PCAP_FILES["ddos_clean"], "DDoS Clean (mitigated)")

if df_unmit.empty or df_raw.empty:
    print("  [!] PCAP DDoS (unmitigated/raw) kosong. Tidak bisa lanjut.")
    sys.exit(1)

has_clean = not df_clean.empty

mitigation_times = {}
if os.path.exists(MITIGATION_CSV):
    try:
        mit_df = pd.read_csv(MITIGATION_CSV)
        mit_df["timestamp"] = pd.to_datetime(mit_df["timestamp"], errors="coerce")
        if "action" in mit_df.columns:
            drop_rows = mit_df[mit_df["action"].astype(str).str.contains("DROP_ICMP", na=False)]
            for ip, grp in drop_rows.groupby("src_ip"):
                mitigation_times[str(ip).strip()] = grp["timestamp"].min()
        print(f"\n  [i] Loaded {len(mitigation_times)} mitigation timestamps")
    except Exception as e:
        print(f"  [!] Gagal load mitigation CSV: {e}")

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 5 — Top Source Host (dari skenario unmitigated, volume utuh)
# ════════════════════════════════════════════════════════════════════════════

def graph_5():
    fn = "G5_top_source_host.png"
    top_n = 12
    counts = df_unmit["src"].value_counts().head(top_n)
    if counts.empty:
        print(f"  [!] Skip {fn}: no host data"); return

    fig, ax = plt.subplots(figsize=(13, 7))
    labels      = counts.index.tolist()
    values      = counts.values
    bar_colors  = [PALETTE["attack"] if ip in ATTACKER_IPS else PALETTE["normal"] for ip in labels]
    host_labels = [f"{ip_to_host(ip)} ({ip})" for ip in labels]

    bars = ax.barh(host_labels[::-1], values[::-1], color=bar_colors[::-1],
                   height=0.65, zorder=3, edgecolor="white", linewidth=1.1)
    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + max(values)*0.01,
                bar.get_y() + bar.get_height()/2,
                f"{val:,}", va="center", ha="left",
                fontsize=10, fontweight="bold", color=PALETTE["text"])

    ax.set_title(f"DDoS Tanpa Mitigasi — Top {top_n} Source Host (by Packet Count)")
    subtitle(ax, "MERAH = attacker | BIRU = normal host | Volume utuh tanpa terpotong drop rule")
    ax.set_xlabel("Jumlah Paket (data plane)")
    ax.set_xlim(0, max(values) * 1.18)
    ax.set_axisbelow(True)

    legend_handles = [
        mpatches.Patch(color=PALETTE["attack"], label="Attacker host"),
        mpatches.Patch(color=PALETTE["normal"], label="Normal host"),
    ]
    ax.legend(handles=legend_handles, loc="lower right")
    save(fn)

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 6 — Cliff Effect: Raw vs Clean (Skenario Mitigated)
# ════════════════════════════════════════════════════════════════════════════

def graph_6():
    fn = "G6_cliff_effect_raw_vs_clean.png"
    fig, ax = plt.subplots(figsize=(16, 7))

    def agg_attacker(df):
        atk = df[(df["src"].isin(ATTACKER_IPS)) & (df["dst"] == VICTIM_IP) &
                 (df["protocol"] == "ICMP")].copy()
        if atk.empty:
            return pd.Series(dtype=float)
        atk.set_index("datetime", inplace=True)
        return atk["size"].resample("1S").count().fillna(0)

    def agg_baseline(df):
        bsl = df[(~df["src"].isin(ATTACKER_IPS)) & (df["dst"] == VICTIM_IP) &
                 (df["protocol"] == "ICMP")].copy()
        if bsl.empty:
            return pd.Series(dtype=float)
        bsl.set_index("datetime", inplace=True)
        return bsl["size"].resample("1S").count().fillna(0)

    raw_attacker = agg_attacker(df_raw)
    raw_baseline = agg_baseline(df_raw)

    if not raw_attacker.empty:
        ax.plot(raw_attacker.index, raw_attacker.values, color=PALETTE["attack"],
                linewidth=2.0, alpha=0.85, label="Raw: Attacker → Victim (ICMP)",
                marker="o", markersize=2)
        ax.fill_between(raw_attacker.index, raw_attacker.values, 0,
                        color=PALETTE["attack"], alpha=0.12)

    if not raw_baseline.empty:
        ax.plot(raw_baseline.index, raw_baseline.values, color=PALETTE["baseline"],
                linewidth=2.0, alpha=0.85, label="Baseline: Normal Host → Victim",
                marker="s", markersize=2)
        ax.fill_between(raw_baseline.index, raw_baseline.values, 0,
                        color=PALETTE["baseline"], alpha=0.12)

    if has_clean:
        clean_attacker = agg_attacker(df_clean)
        if not clean_attacker.empty:
            ax.plot(clean_attacker.index, clean_attacker.values, color=PALETTE["drop"],
                    linewidth=1.8, alpha=0.9, linestyle="--",
                    label="Clean: Attacker (post-drop removed)", marker="^", markersize=2)

    for idx, ip in enumerate(ATTACKER_IPS):
        t = mitigation_times.get(ip)
        if t is None or pd.isna(t):
            continue
        color = ATTACKER_COLORS[idx]
        ax.axvline(t, color=color, linestyle=":", linewidth=1.5, alpha=0.7)
        ax.annotate(f"DROP\n{ATTACKERS[ip]['host']}",
                    xy=(t, ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 100),
                    xytext=(3, -25), textcoords="offset points",
                    fontsize=7, color=color, fontweight="bold")

    ax.set_title("DDoS Dengan Mitigasi — Packet Rate: Raw vs Clean (Cliff Effect)")
    subtitle(ax, "Garis merah putus drastis = mitigasi berhasil | Garis hijau (baseline) tetap mengalir")
    ax.set_xlabel("Time")
    ax.set_ylabel("Packets per Second")
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper right", fontsize=8)
    ax.set_axisbelow(True)
    save(fn)

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 7 — Throughput Performa (2 panel: Unmitigated vs Mitigated)
# ════════════════════════════════════════════════════════════════════════════

def _throughput_mbps(df, is_attacker_side):
    """Hitung throughput (Mbps) per 1 detik untuk attacker atau baseline traffic ke victim."""
    if is_attacker_side:
        sub = df[(df["src"].isin(ATTACKER_IPS)) & (df["dst"] == VICTIM_IP) &
                 (df["protocol"] == "ICMP")].copy()
    else:
        sub = df[(~df["src"].isin(ATTACKER_IPS)) & (df["dst"] == VICTIM_IP) &
                 (df["protocol"] == "ICMP")].copy()
    if sub.empty:
        return pd.Series(dtype=float)
    sub.set_index("datetime", inplace=True)
    bytes_per_sec = sub["size"].resample("1S").sum().fillna(0)
    mbps = (bytes_per_sec * 8) / 1_000_000
    return mbps

def graph_7():
    fn = "G7_throughput_performance.png"
    fig, axes = plt.subplots(1, 2, figsize=(17, 7), sharey=True)

    # Panel kiri: Unmitigated (performa tetap "down")
    ax1 = axes[0]
    atk_tp_unmit = _throughput_mbps(df_unmit, True)
    bsl_tp_unmit = _throughput_mbps(df_unmit, False)
    if not atk_tp_unmit.empty:
        ax1.plot(atk_tp_unmit.index, atk_tp_unmit.values, color=PALETTE["unmit"],
                 linewidth=2.2, label="Throughput Attacker → Victim", marker="o", markersize=2)
        ax1.fill_between(atk_tp_unmit.index, atk_tp_unmit.values, 0,
                         color=PALETTE["unmit"], alpha=0.15)
    if not bsl_tp_unmit.empty:
        ax1.plot(bsl_tp_unmit.index, bsl_tp_unmit.values, color=PALETTE["mit"],
                 linewidth=2.0, label="Throughput Baseline → Victim", marker="s", markersize=2)
    ax1.set_title("Tanpa Mitigasi — Performa Tetap Terganggu")
    subtitle(ax1, "Throughput attacker tetap tinggi sepanjang sesi — network tidak pernah pulih")
    ax1.set_xlabel("Time")
    ax1.set_ylabel("Throughput (Mbps)")
    ax1.tick_params(axis="x", rotation=30)
    ax1.legend(loc="upper right", fontsize=8)
    ax1.set_axisbelow(True)

    # Panel kanan: Mitigated (performa pulih)
    ax2 = axes[1]
    atk_tp_mit = _throughput_mbps(df_raw, True)
    bsl_tp_mit = _throughput_mbps(df_raw, False)
    if not atk_tp_mit.empty:
        ax2.plot(atk_tp_mit.index, atk_tp_mit.values, color=PALETTE["unmit"],
                 linewidth=2.2, label="Throughput Attacker → Victim", marker="o", markersize=2)
        ax2.fill_between(atk_tp_mit.index, atk_tp_mit.values, 0,
                         color=PALETTE["unmit"], alpha=0.15)
    if not bsl_tp_mit.empty:
        ax2.plot(bsl_tp_mit.index, bsl_tp_mit.values, color=PALETTE["mit"],
                 linewidth=2.0, label="Throughput Baseline → Victim", marker="s", markersize=2)

    for idx, ip in enumerate(ATTACKER_IPS):
        t = mitigation_times.get(ip)
        if t is None or pd.isna(t):
            continue
        color = ATTACKER_COLORS[idx]
        ax2.axvline(t, color=color, linestyle=":", linewidth=1.5, alpha=0.7)

    ax2.set_title("Dengan Mitigasi — Performa Pulih Setelah DROP")
    subtitle(ax2, "Garis titik = waktu DROP per attacker. Throughput attacker turun ke 0, baseline tetap stabil")
    ax2.set_xlabel("Time")
    ax2.tick_params(axis="x", rotation=30)
    ax2.legend(loc="upper right", fontsize=8)
    ax2.set_axisbelow(True)

    fig.suptitle("Analisis Performa Jaringan: Throughput ke Victim — Down vs Recovery",
                 fontsize=14, fontweight="bold", y=1.03)
    save(fn)

    return {
        "unmit_avg_attacker_mbps": float(atk_tp_unmit.mean()) if not atk_tp_unmit.empty else 0,
        "mit_avg_attacker_mbps_pre": float(atk_tp_mit[atk_tp_mit.index < min(
            [t for t in mitigation_times.values() if not pd.isna(t)], default=atk_tp_mit.index.max()
        )].mean()) if not atk_tp_mit.empty and mitigation_times else 0,
        "baseline_avg_mbps": float(bsl_tp_mit.mean()) if not bsl_tp_mit.empty else 0,
    }

# ─── Jalankan semua grafik ──────────────────────────────────────────────────

print("\n[*] Generating PCAP-based graphs ...")
graph_5()
graph_6()
tp_result = graph_7()

# ─── Markdown report ──────────────────────────────────────────────────────────

print("\n[*] Writing pcap_summary.md ...")
md_path = out("pcap_summary.md")
NOW = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def quick_stats(df, label):
    if df.empty:
        return f"| {label} | 0 | — | — |"
    dur = df["timestamp"].max() - df["timestamp"].min()
    return f"| {label} | {len(df):,} | {dur:.1f}s | {len(df)/dur if dur>0 else 0:.1f} pps |"

stats_rows = [
    quick_stats(df_baseline, "Baseline"),
    quick_stats(df_unmit, "DDoS Tanpa Mitigasi"),
    quick_stats(df_raw, "DDoS Raw (Mitigated)"),
]
if has_clean:
    stats_rows.append(quick_stats(df_clean, "DDoS Clean (Mitigated)"))

top_hosts = df_unmit["src"].value_counts().head(10)
host_rows = []
for ip, count in top_hosts.items():
    status = "⚠️ **ATTACKER**" if ip in ATTACKER_IPS else "✅ normal"
    host_rows.append(f"| `{ip}` ({ip_to_host(ip)}) | {count:,} | {status} |")

md_content = f"""# PCAP Forensic Analysis — 3 Skenario

**Generated:** {NOW}
**Data source:** PCAP baseline, ddos_unmitigated, ddos (raw + clean)

---

## 1. Metadata PCAP

| Skenario | Total Paket | Durasi | Rate Rata-rata |
|----------|------------:|-------:|----------------:|
{chr(10).join(stats_rows)}

---

## 2. Top Source Host (DDoS Tanpa Mitigasi)

| Source | Packets | Status |
|--------|--------:|--------|
{chr(10).join(host_rows)}

![Top Source Host](G5_top_source_host.png)

---

## 3. Cliff Effect (DDoS Dengan Mitigasi)

![Cliff Effect Raw vs Clean](G6_cliff_effect_raw_vs_clean.png)

---

## 4. Analisis Performa Jaringan (Throughput)

| Metrik | Nilai |
|--------|------:|
| Rata-rata throughput attacker (tanpa mitigasi) | {tp_result['unmit_avg_attacker_mbps']:.2f} Mbps |
| Rata-rata throughput attacker sebelum drop (dengan mitigasi) | {tp_result['mit_avg_attacker_mbps_pre']:.2f} Mbps |
| Rata-rata throughput baseline (kondisi normal) | {tp_result['baseline_avg_mbps']:.2f} Mbps |

Tanpa mitigasi, throughput menuju victim tetap tinggi sepanjang sesi —
jaringan tidak pernah kembali ke kondisi normal. Dengan mitigasi, throughput
attacker turun signifikan setelah DROP rule terpasang, sementara throughput
baseline tetap stabil sepanjang waktu.

![Throughput Performance](G7_throughput_performance.png)

---

*Di-generate otomatis oleh `analyze_pcap.py`. Untuk analisis CSV, lihat `csv_summary.md`.*
"""

with open(md_path, "w", encoding="utf-8") as f:
    f.write(md_content)
print(f"  [+] pcap_summary.md")

print(f"\n{'='*60}")
print(f"  PCAP ANALYSIS DONE — Output: {OUTPUT_DIR}")
print(f"{'='*60}\n")
