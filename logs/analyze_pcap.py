"""
analyze_pcap.py
================

Analyzer PCAP final untuk Bab V TA.

Output utama (revisi - total 6 PNG):
1. Top Source Host per skenario -> 1 PNG per skenario (3 file)
2. Pie chart distribusi protokol (ICMP/ARP/TCP/UDP/OTHER) per skenario -> 1 PNG per skenario (3 file)

Catatan penting:
- Skenario DDoS dengan mitigasi menggunakan network_ddos_clean.pcap
  karena grafik utama harus merepresentasikan traffic yang masih lolos
  setelah mitigasi, bukan raw traffic.
- Attacker hanya diberi 1 warna merah (tidak dibedakan per host attacker).

Output:
- /home/kali/sdn-icmp/logs/charts/
"""

import os
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
import seaborn as sns


# ============================================================
# 0. KONFIGURASI
# ============================================================

BASE_DIR = "/home/kali/sdn-icmp"
OUT_DIR = "/home/kali/sdn-icmp/logs/charts"
os.makedirs(OUT_DIR, exist_ok=True)

PCAP_BASELINE = f"{BASE_DIR}/logs/archive/baseline/network_baseline.pcap"
PCAP_UNMIT = f"{BASE_DIR}/logs/archive/ddos_unmitigated/network_ddos_unmitigated.pcap"

# Raw PCAP tetap dicatat sebagai referensi, tetapi tidak dipakai untuk grafik utama
PCAP_MIT_RAW = f"{BASE_DIR}/logs/archive/ddos/network_ddos.pcap"

# Grafik utama mitigasi memakai clean PCAP
PCAP_MIT_CLEAN = f"{BASE_DIR}/logs/archive/ddos/network_ddos_clean.pcap"

VICTIM_IP = "10.0.0.25"

ATTACKER_IPS = [
    "10.0.0.1",
    "10.0.0.7",
    "10.0.0.13",
    "10.0.0.18",
]

HOST_NAMES = {
    "10.0.0.1": "h1",
    "10.0.0.2": "h2",
    "10.0.0.3": "h3",
    "10.0.0.4": "h4",
    "10.0.0.5": "h5",
    "10.0.0.6": "h6",
    "10.0.0.7": "h7",
    "10.0.0.8": "h8",
    "10.0.0.9": "h9",
    "10.0.0.10": "h10",
    "10.0.0.11": "h11",
    "10.0.0.12": "h12",
    "10.0.0.13": "h13",
    "10.0.0.14": "h14",
    "10.0.0.15": "h15",
    "10.0.0.16": "h16",
    "10.0.0.17": "h17",
    "10.0.0.18": "h18",
    "10.0.0.19": "h19",
    "10.0.0.20": "h20",
    "10.0.0.21": "h21",
    "10.0.0.22": "h22",
    "10.0.0.23": "h23",
    "10.0.0.24": "h24",
    "10.0.0.25": "h25",
}


# ============================================================
# 1. STYLE UI
# ============================================================

SCEN_COLORS = {
    "Baseline": "#4daf4a",
    "DDoS Tanpa Mitigasi": "#e41a1c",
    "DDoS Dengan Mitigasi": "#377eb8",
}

# Attacker hanya diberi 1 warna merah (tidak dibedakan per host attacker).
ATTACKER_COLOR = "#e41a1c"

PROTO_COLORS = {
    "ICMP": "#4A90D9",
    "ARP": "#8E44AD",
    "TCP": "#27AE60",
    "UDP": "#F5A623",
    "OTHER": "#95A5A6",
}

NORMAL_COLOR = "#95A5A6"
OTHER_COLOR = "#D0D3D4"

sns.set_theme(style="whitegrid", context="talk")

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#BDC3C7",
    "axes.grid": True,
    "grid.color": "#ECEFF1",
    "grid.linewidth": 0.8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.titlesize": 14,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "font.family": "DejaVu Sans",
    "figure.dpi": 130,
})


# ============================================================
# 2. HELPER
# ============================================================

def check_tshark():
    try:
        result = subprocess.run(
            ["tshark", "-v"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def tshark_extract(pcap_path, fields):
    cmd = ["tshark", "-r", pcap_path, "-T", "fields"]

    for field in fields:
        cmd += ["-e", field]

    cmd += ["-E", "separator=|", "-E", "occurrence=f"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        if result.returncode != 0:
            print(f"  [!] tshark error: {result.stderr[:300]}")
            return []

    except subprocess.TimeoutExpired:
        print("  [!] tshark timeout")
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


def classify_proto(row):
    if row.get("arp.opcode"):
        return "ARP"

    ip_proto = row.get("ip.proto", "")

    if ip_proto == "1":
        return "ICMP"
    if ip_proto == "6":
        return "TCP"
    if ip_proto == "17":
        return "UDP"

    return "OTHER"


def load_pcap(path, label):
    if not os.path.exists(path):
        print(f"  [!] File tidak ditemukan: {path}")
        return pd.DataFrame()

    file_size_mb = os.path.getsize(path) / 1024 / 1024

    print(f"\n[*] Loading {label}")
    print(f"    File : {os.path.basename(path)}")
    print(f"    Size : {file_size_mb:.2f} MB")

    fields = [
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "arp.opcode",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "icmp.type",
    ]

    rows = tshark_extract(path, fields)

    print(f"    Paket diekstrak: {len(rows):,}")

    if not rows:
        return pd.DataFrame()

    records = []

    for row in rows:
        proto = classify_proto(row)

        src = row.get("ip.src") or row.get("arp.src.proto_ipv4") or ""
        dst = row.get("ip.dst") or row.get("arp.dst.proto_ipv4") or ""

        try:
            ts = float(row.get("frame.time_epoch", 0))
        except (ValueError, TypeError):
            ts = 0.0

        try:
            size = int(row.get("frame.len", 0))
        except (ValueError, TypeError):
            size = 0

        records.append({
            "ts": ts,
            "size": size,
            "src": src,
            "dst": dst,
            "proto": proto,
            "icmp_type": row.get("icmp.type", ""),
            "scenario": label,
        })

    df = pd.DataFrame(records)

    if df.empty:
        return df

    df["elapsed"] = df["ts"] - df["ts"].min()

    return df


def save_chart(filename):
    output_path = os.path.join(OUT_DIR, filename)
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"  [+] Tersimpan: {filename}")


def host_label(ip):
    if ip == "Others":
        return "Others"

    if ip in HOST_NAMES:
        return f"{HOST_NAMES[ip]} ({ip})"

    if isinstance(ip, str) and ip.startswith("10.0.0."):
        return f"h{ip.split('.')[-1]} ({ip})"

    if ip == "":
        return "Unknown"

    return str(ip)


def scenario_slug(scenario_label):
    return (
        scenario_label.lower()
        .replace(" ", "_")
        .replace("(", "")
        .replace(")", "")
    )


# ============================================================
# 3. LOAD DATA
# ============================================================

print("\n" + "=" * 72)
print("  SDN PCAP FORENSIC ANALYZER - FINAL CLEAN PCAP")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 72)

if not check_tshark():
    print("  [!] tshark belum terpasang.")
    print("      Install dengan: sudo apt install -y tshark")
    exit(1)

df_base = load_pcap(PCAP_BASELINE, "Baseline")
df_unmit = load_pcap(PCAP_UNMIT, "DDoS Tanpa Mitigasi")
df_mit = load_pcap(PCAP_MIT_CLEAN, "DDoS Dengan Mitigasi")

if df_base.empty:
    print("  [!] Baseline PCAP kosong/tidak terbaca.")

if df_unmit.empty:
    print("  [!] Unmitigated PCAP kosong/tidak terbaca.")

if df_mit.empty:
    print("  [!] Mitigated clean PCAP kosong/tidak terbaca.")

if df_base.empty and df_unmit.empty and df_mit.empty:
    print("  [!] Semua PCAP kosong. Program dihentikan.")
    exit(1)

SCENARIO_DATA = [
    ("Baseline", df_base),
    ("DDoS Tanpa Mitigasi", df_unmit),
    ("DDoS Dengan Mitigasi", df_mit),
]


# ============================================================
# 4. TOP SOURCE HOST (1 PNG per skenario)
# ============================================================

def get_top_source_counts(df, top_n=8, exclude_victim=True):
    if df.empty:
        return pd.Series(dtype=int), 0

    # Filter khusus untuk V.2:
    # hanya menghitung ICMP echo request yang menuju victim.
    src_df = df[
        (df["src"] != "") &
        (df["dst"] == VICTIM_IP) &
        (df["proto"] == "ICMP") &
        (df["icmp_type"] == "8")
    ].copy()

    if exclude_victim:
        src_df = src_df[src_df["src"] != VICTIM_IP]

    if src_df.empty:
        return pd.Series(dtype=int), 0

    counts = src_df["src"].value_counts()
    total_source_packets = int(counts.sum())

    top_counts = counts.head(top_n).copy()

    if len(counts) > top_n:
        others_value = int(counts.iloc[top_n:].sum())

        if others_value > 0:
            top_counts.loc["Others"] = others_value

    return top_counts, total_source_packets

def bar_color_for_source(source):
    if source in ATTACKER_IPS:
        return ATTACKER_COLOR

    if source == "Others":
        return OTHER_COLOR

    return NORMAL_COLOR


def chart_top_source_host(scenario, df, note_suffix=""):
    counts, total_source_packets = get_top_source_counts(
        df=df,
        top_n=8,
        exclude_victim=True
    )

    fig, ax = plt.subplots(figsize=(12, 6.5))

    if counts.empty:
        ax.set_title(f"{scenario} - Data kosong", fontsize=13, fontweight="bold")
        ax.axis("off")
        filename = f"top_source_host_{scenario_slug(scenario)}.png"
        save_chart(filename)
        return

    labels = counts.index.tolist()
    values = counts.values.astype(int).tolist()

    y_positions = np.arange(len(labels))

    colors = [bar_color_for_source(label) for label in labels]
    readable_labels = [host_label(label) for label in labels]

    bars = ax.barh(
        y_positions,
        values,
        color=colors,
        edgecolor="white",
        linewidth=1.0,
        height=0.65,
        zorder=3
    )

    ax.set_yticks(y_positions)
    ax.set_yticklabels(readable_labels)
    ax.invert_yaxis()

    max_value = max(values)

    for bar, source, value in zip(bars, labels, values):
        pct = value / total_source_packets * 100 if total_source_packets else 0

        ax.text(
            value + max_value * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{value:,} pkt | {pct:.1f}%",
            va="center",
            ha="left",
            fontsize=9,
            fontweight="bold",
            color="#2C3E50"
        )

    ax.set_xlabel("Jumlah paket")
    ax.set_xlim(0, max_value * 1.22)
    ax.grid(axis="x", alpha=0.6)
    ax.grid(axis="y", visible=False)
    ax.set_axisbelow(True)

    ax.set_title(
        f"Top Source Host Incoming ICMP Request Menuju Victim - {scenario}",
        fontsize=14,
        fontweight="bold",
        loc="left",
        pad=14,
    )

    legend_handles = [
        mpatches.Patch(color=ATTACKER_COLOR, label="Host attacker"),
        mpatches.Patch(color=NORMAL_COLOR, label="Host normal"),
        mpatches.Patch(color=OTHER_COLOR, label="Others"),
    ]
    ax.legend(handles=legend_handles, loc="lower right", frameon=True, framealpha=0.92)

    note = (
        f"Filter: icmp.type == 8 && ip.dst == {VICTIM_IP} "
        f"| Total packet dianalisis: {total_source_packets:,}"
    )
    if note_suffix:
        note += f" | {note_suffix}"

    fig.text(
        0.01,
        -0.03,
        note,
        fontsize=8.5,
        color="#7F8C8D",
        style="italic"
    )

    filename = f"top_source_host_{scenario_slug(scenario)}.png"
    save_chart(filename)


# ============================================================
# 5. PIE CHART DISTRIBUSI PROTOKOL (1 PNG per skenario)
# ============================================================

def protocol_label_text(counts, ordered_protocols, total):
    lines = []

    for proto in ordered_protocols:
        value = int(counts.get(proto, 0))
        pct = value / total * 100 if total else 0
        lines.append(f"{proto}: {pct:.1f}% ({value:,})")

    return "\n".join(lines)


def chart_protocol_distribution(scenario, df, note_suffix=""):
    fig, ax = plt.subplots(figsize=(8, 8))

    if df.empty:
        ax.set_title(f"{scenario} - Data kosong", fontsize=13, fontweight="bold")
        ax.axis("off")
        filename = f"protocol_distribution_{scenario_slug(scenario)}.png"
        save_chart(filename)
        return

    counts = df["proto"].value_counts()

    ordered_protocols = [
        proto for proto in ["ICMP", "ARP", "TCP", "UDP", "OTHER"]
        if proto in counts.index
    ]

    values = [int(counts[proto]) for proto in ordered_protocols]
    colors = [PROTO_COLORS.get(proto, OTHER_COLOR) for proto in ordered_protocols]
    total = int(sum(values))

    ax.pie(
        values,
        labels=None,
        colors=colors,
        startangle=90,
        counterclock=False,
        wedgeprops={
            "width": 0.38,
            "edgecolor": "white",
            "linewidth": 2,
        },
    )

    ax.text(
        0,
        0.05,
        f"{total:,}",
        ha="center",
        va="center",
        fontsize=15,
        fontweight="bold",
        color="#2C3E50"
    )

    ax.text(
        0,
        -0.13,
        "total paket",
        ha="center",
        va="center",
        fontsize=9,
        color="#7F8C8D"
    )

    ax.set_title(f"Distribusi Protokol - {scenario}", fontsize=14, fontweight="bold", pad=14)
    ax.axis("equal")

    label_text = protocol_label_text(counts, ordered_protocols, total)

    ax.text(
        0,
        -1.32,
        label_text,
        ha="center",
        va="top",
        fontsize=9.5,
        color="#34495E",
        linespacing=1.5
    )

    proto_handles = [
        mpatches.Patch(color=PROTO_COLORS[proto], label=proto)
        for proto in ["ICMP", "ARP", "TCP", "UDP", "OTHER"]
        if proto in ordered_protocols
    ]
    ax.legend(
        handles=proto_handles,
        loc="upper left",
        bbox_to_anchor=(-0.25, 1.1),
        frameon=False,
        fontsize=9,
    )

    note = "Kategori: ICMP / ARP / TCP / UDP / OTHER."
    if note_suffix:
        note += f" {note_suffix}"

    fig.text(
        0.5,
        -0.02,
        note,
        ha="center",
        fontsize=8.5,
        color="#7F8C8D",
        style="italic"
    )

    filename = f"protocol_distribution_{scenario_slug(scenario)}.png"
    save_chart(filename)


# ============================================================
# 6. EKSEKUSI
# ============================================================

if __name__ == "__main__":
    print("\n[*] Membuat grafik PCAP final...\n")

    print("  [1] Top Source Host per Skenario (3 PNG)")
    for scenario, df in SCENARIO_DATA:
        note = "Skenario mitigasi menggunakan network_ddos_clean.pcap." if scenario == "DDoS Dengan Mitigasi" else ""
        chart_top_source_host(scenario, df, note_suffix=note)

    print("\n  [2] Distribusi Protokol per Skenario (3 PNG)")
    for scenario, df in SCENARIO_DATA:
        note = "Skenario mitigasi menggunakan network_ddos_clean.pcap." if scenario == "DDoS Dengan Mitigasi" else ""
        chart_protocol_distribution(scenario, df, note_suffix=note)

    print("\n" + "=" * 72)
    print(f"  SELESAI - Output tersimpan di: {OUT_DIR} (total 6 PNG)")
    print("=" * 72 + "\n")