#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_csv_final.py
====================
Analyzer CSV final untuk laporan TA SDN ICMP Flood.

UPDATED (revisi struktur folder, controller final, & cakupan output):
  - Path skenario disesuaikan dengan struktur logs/archive/ final:
      baseline/, ddos_unmitigated/, ddos_mitigated/
    (sebelumnya skrip ini masih memakai folder lama "ddos" untuk
    skenario mitigasi, yang sudah tidak ada lagi di struktur final.)
  - Kolom final_prediction DIHAPUS total dari alur analisis, karena
    controller final tidak lagi menghasilkan kolom itu (SVM sudah
    dihapus; traffic_analysis.csv sekarang 12 kolom, bukan 13).
    Semua logika yang sebelumnya membaca final_prediction sekarang
    diturunkan dari detection_status (NORMAL/WARNING/ATTACK_CONFIRMED).
  - Grafik "packet/s per host" dan "Confusion Matrix (P3)" DIHAPUS
    total dari skrip ini karena tidak lagi dipakai pada laporan Bab V.
    Skrip sekarang hanya menghasilkan satu jenis output: distribusi
    status deteksi per skenario.
  - Label sumbu grafik distribusi status diubah dari
    "Jumlah Event / Paket" menjadi "Jumlah Event" (lebih akurat,
    karena grafik ini murni menghitung baris/event pada
    traffic_analysis.csv, bukan paket PCAP).

Output utama:
  1. Pie chart (bar horizontal) distribusi status deteksi -> 1 PNG per skenario
     (Normal / Warning / Attack Confirmed / Mitigation)

Catatan:
  - Jangan simpan file ini dengan nama csv.py karena akan bentrok dengan library bawaan Python "csv".
  - Jalankan dari folder logs atau root project tetap aman karena path bersifat absolut.

Cara pakai:
  cd /home/kali/sdn-icmp/logs
  python3 analyze_csv_final.py

Output:
  /home/kali/sdn-icmp/logs/charts/
"""

from pathlib import Path

import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns


# ============================================================
# 0. KONFIGURASI
# ============================================================

BASE_DIR = Path("/home/kali/sdn-icmp/logs/archive")
OUT_DIR = Path("/home/kali/sdn-icmp/logs/charts")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# UPDATED: folder skenario mitigasi final bernama "ddos_mitigated",
# bukan "ddos" seperti versi sebelumnya.
PATH_BASELINE = BASE_DIR / "baseline" / "traffic_analysis.csv"
PATH_UNMIT = BASE_DIR / "ddos_unmitigated" / "traffic_analysis.csv"
PATH_MIT = BASE_DIR / "ddos_mitigated" / "traffic_analysis.csv"
PATH_MIT_EVENTS = BASE_DIR / "ddos_mitigated" / "mitigation_events.csv"

VICTIM_IP = "10.0.0.25"
FALLBACK_ATTACKERS = ["10.0.0.1", "10.0.0.7", "10.0.0.13", "10.0.0.18"]
FALLBACK_HOST_NAMES = {
    "10.0.0.1": "h1",
    "10.0.0.7": "h7",
    "10.0.0.13": "h13",
    "10.0.0.18": "h18",
}

ATTACKER_COLORS = {
    "10.0.0.1": "#E41A1C",    # merah
    "10.0.0.7": "#377EB8",    # biru
    "10.0.0.13": "#4DAF4A",   # hijau
    "10.0.0.18": "#984EA3",   # ungu
}
NORMAL_HOST_PALETTE = sns.color_palette("tab10", 10).as_hex()

PIE_COLOR_NORMAL = "#3B82F6"      # biru
PIE_COLOR_WARNING = "#F5C518"     # kuning
PIE_COLOR_ATTACK = "#E63946"      # merah
PIE_COLOR_MITIGATION = "#8E44AD"  # ungu

SCENARIOS = ["Baseline", "Unmitigated", "Mitigated"]
MAX_HOST_LINES = 6

sns.set_theme(style="whitegrid", context="paper")
plt.rcParams.update({
    "figure.dpi": 180,
    "savefig.dpi": 220,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#D0D0D0",
    "axes.grid": True,
    "grid.color": "#EAEAEA",
    "grid.linewidth": 0.8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "font.family": "DejaVu Sans",
    "axes.titlesize": 14,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
})


# ============================================================
# 1. LOAD & PREPROCESSING
# ============================================================

def require_file(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")


def load_traffic(path: Path, scenario_label: str) -> pd.DataFrame:
    require_file(path)
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    df["scenario"] = scenario_label
    df["elapsed"] = (df["timestamp"] - df["timestamp"].min()).dt.total_seconds()

    # UPDATED: final_prediction dihapus dari daftar kolom numerik karena
    # sudah tidak ada di CSV controller final (12 kolom, no SVM).
    for col in ["packet_rate", "packet_count", "threat_score"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def load_mitigation_events(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    if "action" in df.columns:
        df = df[df["action"].astype(str).str.contains("DROP_ICMP", na=False)].copy()
    return df.sort_values("timestamp").reset_index(drop=True)


print("[INFO] Membaca CSV eksperimen...")
base = load_traffic(PATH_BASELINE, "Baseline")
unmit = load_traffic(PATH_UNMIT, "Unmitigated")
mit = load_traffic(PATH_MIT, "Mitigated")
mit_events = load_mitigation_events(PATH_MIT_EVENTS)

DATA_BY_SCENARIO = {"Baseline": base, "Unmitigated": unmit, "Mitigated": mit}

if not mit_events.empty:
    ATTACKERS = list(dict.fromkeys([str(ip).strip() for ip in mit_events["src_ip"].dropna().tolist()]))
    HOST_NAMES = dict(zip(mit_events["src_ip"].astype(str), mit_events["attacker_hostname"].astype(str)))
    BLOCK_TIME_ABS = dict(zip(mit_events["src_ip"].astype(str), mit_events["timestamp"]))
else:
    ATTACKERS = FALLBACK_ATTACKERS
    HOST_NAMES = FALLBACK_HOST_NAMES
    BLOCK_TIME_ABS = {}

# Skenario mana saja yang punya event DROP (biasanya hanya "Mitigated")
SCENARIO_HAS_DROP = {
    "Baseline": False,
    "Unmitigated": False,
    "Mitigated": bool(BLOCK_TIME_ABS),
}

print(f"[INFO] Victim   : {VICTIM_IP}")
print(f"[INFO] Attackers: {', '.join([HOST_NAMES.get(ip, ip) + ' (' + ip + ')' for ip in ATTACKERS])}")
print(f"[INFO] DROP rows: {len(mit_events)}")


# ============================================================
# 2. HELPER
# ============================================================

def one_second_count(df: pd.DataFrame, full_index: pd.DatetimeIndex) -> pd.Series:
    if df.empty:
        return pd.Series(0, index=full_index, dtype=float)
    ts = df.set_index("timestamp").resample("1s").size()
    ts = ts.reindex(full_index, fill_value=0).astype(float)
    return ts


def savefig(fig, filename: str):
    out_path = OUT_DIR / filename
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[OK] Tersimpan: {out_path}")


def host_label(ip: str) -> str:
    name = HOST_NAMES.get(ip)
    return f"{name} ({ip})" if name and name != "nan" else ip


def host_color(ip: str, idx: int, is_attacker: bool = False) -> str:
    if is_attacker and ip in ATTACKER_COLORS:
        return ATTACKER_COLORS[ip]
    return NORMAL_HOST_PALETTE[idx % len(NORMAL_HOST_PALETTE)]


# ============================================================
# 3. PIE CHART - DISTRIBUSI STATUS DETEKSI (1 PNG per skenario)
# ============================================================

STATUS_ORDER = ["Normal", "Warning", "Attack Confirmed", "Mitigation"]
STATUS_COLORS = {
    "Normal": PIE_COLOR_NORMAL,
    "Warning": PIE_COLOR_WARNING,
    "Attack Confirmed": PIE_COLOR_ATTACK,
    "Mitigation": PIE_COLOR_MITIGATION,
}


def classify_status(df: pd.DataFrame) -> pd.Series:
    """
    Mengembalikan kolom kategori status deteksi per baris, diambil dari
    kolom `detection_status` (Normal / Warning / Attack Confirmed).

    UPDATED: fallback lama yang memakai final_prediction dihapus total
    -- controller final selalu menuliskan detection_status, sehingga
    fallback itu tidak lagi relevan dan justru menyesatkan kalau
    dipertahankan (kolom final_prediction sudah tidak eksis).
    """
    if "detection_status" not in df.columns:
        raise KeyError(
            "Kolom 'detection_status' tidak ditemukan. Pastikan CSV berasal "
            "dari controller final (12 kolom, tanpa final_prediction)."
        )
    status = df["detection_status"].astype(str).str.strip()
    norm_map = {
        "normal": "Normal",
        "warning": "Warning",
        "attack_confirmed": "Attack Confirmed",
        "attack confirmed": "Attack Confirmed",
    }
    status = status.apply(lambda s: norm_map.get(s.lower(), s))
    return status


def chart_pie_status_deteksi(df: pd.DataFrame, scenario_label: str):
    if df.empty:
        print(f"[SKIP] Pie status deteksi ({scenario_label}): data kosong.")
        return

    status = classify_status(df)
    counts = status.value_counts().reindex(["Normal", "Warning", "Attack Confirmed"]).fillna(0).astype(int)

    # "Mitigation" dihitung langsung dari jumlah event DROP_ICMP di
    # mitigation_events.csv, bukan dari baris traffic_analysis.csv setelah
    # waktu drop -- karena begitu flow rule DROP aktif, paket attacker itu
    # tidak lagi diteruskan ke controller sehingga tidak tercatat lagi di
    # traffic_analysis.csv (hitungannya akan selalu 0 kalau dicari di sana).
    if SCENARIO_HAS_DROP.get(scenario_label, False):
        counts["Mitigation"] = len(mit_events)

    counts = counts.reindex(STATUS_ORDER).fillna(0).astype(int)
    counts = counts[counts > 0]

    # Urutan tampil dari atas ke bawah: Normal paling atas.
    counts = counts.iloc[::-1]

    colors = [STATUS_COLORS[label] for label in counts.index]
    total = counts.sum()

    fig_h = max(3.5, 0.9 * len(counts) + 1.8)
    fig, ax = plt.subplots(figsize=(10, fig_h))

    y_pos = np.arange(len(counts))
    bars = ax.barh(
        y_pos,
        counts.values,
        color=colors,
        edgecolor="white",
        linewidth=1.2,
        height=0.6,
        zorder=3,
    )

    ax.set_yticks(y_pos)
    ax.set_yticklabels(counts.index, fontsize=11, fontweight="bold")

    max_val = max(1, int(counts.max()))
    ax.set_xlim(0, max_val * 1.28)
    ax.set_xlabel("Jumlah Event")
    ax.grid(axis="x", alpha=0.5)
    ax.grid(axis="y", visible=False)
    ax.set_axisbelow(True)

    for bar, (label, n) in zip(bars, counts.items()):
        pct = n / total * 100 if total else 0
        ax.text(
            bar.get_width() + max_val * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{n:,}  ({pct:.1f}%)",
            va="center",
            ha="left",
            fontsize=10,
            fontweight="bold",
            color="#2C3E50",
        )

    ax.set_title(
        f"Distribusi Status Deteksi - Skenario {scenario_label}",
        fontweight="bold",
        loc="left",
        pad=14,
    )

    fig.text(
        0.01,
        -0.02 - 0.015 * max(0, 4 - len(counts)),
        f"Total {total:,} baris  |  Sumber: kolom detection_status pada traffic_analysis.csv"
        + (", jumlah event DROP_ICMP pada mitigation_events.csv" if SCENARIO_HAS_DROP.get(scenario_label, False) else ""),
        fontsize=8.5,
        color="#555555",
        style="italic",
    )

    fname = f"pie_status_deteksi_{scenario_label.lower()}.png"
    savefig(fig, fname)


# ============================================================
# 6. EKSEKUSI
# ============================================================

if __name__ == "__main__":
    print("\n[INFO] Membuat grafik CSV final untuk laporan...")

    for scenario_label in SCENARIOS:
        df_scenario = DATA_BY_SCENARIO[scenario_label]
        chart_pie_status_deteksi(df_scenario, scenario_label)

    print(f"\n[SELESAI] Output tersimpan di: {OUT_DIR}")