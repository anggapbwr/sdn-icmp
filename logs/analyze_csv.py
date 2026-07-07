#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_csv_final.py
====================
Analyzer CSV final untuk laporan TA SDN ICMP Flood.

Output utama (revisi):
  1. Pie chart distribusi status deteksi -> 1 file PNG per skenario
     (Normal / Attack Terdeteksi / Attack Terdeteksi & Di-drop)
  2. Grafik packet/s per host -> 1 file PNG per skenario
     (garis vertikal putus-putus menandai waktu DROP dari mitigation_events.csv,
      hanya muncul di skenario yang punya event DROP)
  3. Confusion Matrix Deteksi ICMP Flood (P3) - dipertahankan, gabungan 3 skenario

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
import matplotlib.dates as mdates
import seaborn as sns


# ============================================================
# 0. KONFIGURASI
# ============================================================

BASE_DIR = Path("/home/kali/sdn-icmp/logs/archive")
OUT_DIR = Path("/home/kali/sdn-icmp/logs/charts")
OUT_DIR.mkdir(parents=True, exist_ok=True)

PATH_BASELINE = BASE_DIR / "baseline" / "traffic_analysis.csv"
PATH_UNMIT = BASE_DIR / "ddos_unmitigated" / "traffic_analysis.csv"
PATH_MIT = BASE_DIR / "ddos" / "traffic_analysis.csv"
PATH_MIT_EVENTS = BASE_DIR / "ddos" / "mitigation_events.csv"

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

    for col in ["packet_rate", "packet_count", "threat_score", "final_prediction"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    if "final_prediction" in df.columns:
        df["final_prediction"] = df["final_prediction"].astype(int)

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
    """
    if "detection_status" in df.columns:
        status = df["detection_status"].astype(str).str.strip()
        norm_map = {
            "normal": "Normal",
            "warning": "Warning",
            "attack_confirmed": "Attack Confirmed",
            "attack confirmed": "Attack Confirmed",
        }
        status = status.apply(lambda s: norm_map.get(s.lower(), s))
    else:
        status = pd.Series(
            np.where(df["final_prediction"] == 1, "Attack Confirmed", "Normal"),
            index=df.index,
        )
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
    ax.set_xlabel("Jumlah Event / Paket")
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
# 4. GRAFIK PACKET/S PER HOST (1 PNG per skenario)
# ============================================================

def chart_packet_rate_per_host(df: pd.DataFrame, scenario_label: str):
    if df.empty:
        print(f"[SKIP] Packet/s per host ({scenario_label}): data kosong.")
        return

    start = df["timestamp"].min().floor("s")
    end = df["timestamp"].max().ceil("s")
    full_index = pd.date_range(start=start, end=end, freq="1s")

    all_hosts = df["src_ip"].astype(str).unique().tolist()

    # Baseline = traffic ping antar host normal (pingall), attacker BELUM
    # menyerang, jadi host attacker tidak perlu ditandai warna khusus di sini.
    highlight_attackers = scenario_label != "Baseline"

    attacker_hosts = [ip for ip in all_hosts if highlight_attackers and ip in ATTACKER_COLORS]
    other_hosts_all = [ip for ip in all_hosts if ip not in attacker_hosts]

    volume_by_host = df.groupby(df["src_ip"].astype(str)).size()
    other_hosts_all = sorted(other_hosts_all, key=lambda ip: volume_by_host.get(ip, 0), reverse=True)

    slots_left = max(MAX_HOST_LINES - len(attacker_hosts), 0)
    shown_other_hosts = other_hosts_all[:slots_left]
    lumped_other_hosts = other_hosts_all[slots_left:]

    hosts_to_plot = attacker_hosts + shown_other_hosts

    fig, ax = plt.subplots(figsize=(14.5, 6.2))

    max_y = 1.0
    normal_idx = 0
    for ip in hosts_to_plot:
        sub = df[df["src_ip"].astype(str) == ip]
        ts = one_second_count(sub, full_index).rolling(5, min_periods=1).mean()
        max_y = max(max_y, float(ts.max()))

        is_attacker = ip in attacker_hosts
        color = host_color(ip, normal_idx, is_attacker=is_attacker)
        if not is_attacker:
            normal_idx += 1

        ax.plot(
            ts.index,
            ts.values,
            color=color,
            linewidth=1.1 if is_attacker else 0.8,
            alpha=0.9 if is_attacker else 0.7,
            linestyle="-" if is_attacker else "--",
            label=host_label(ip),
            zorder=3 if is_attacker else 2,
        )

    if lumped_other_hosts:
        other_df = df[df["src_ip"].astype(str).isin(lumped_other_hosts)]
        ts_other = one_second_count(other_df, full_index).rolling(5, min_periods=1).mean()
        max_y = max(max_y, float(ts_other.max()))
        ax.plot(
            ts_other.index,
            ts_other.values,
            color="#B0B0B0",
            linewidth=0.8,
            alpha=0.7,
            linestyle="--",
            label=f"Other hosts ({len(lumped_other_hosts)})",
            zorder=1,
        )

    y_limit = max_y * 1.22 if max_y > 0 else 10
    ax.set_ylim(0, y_limit)

    # Garis DROP: hanya digambar jika skenario ini punya event DROP.
    if SCENARIO_HAS_DROP.get(scenario_label, False):
        label_offsets = [0.95, 0.87, 0.79, 0.71]
        for idx, ip in enumerate(ATTACKERS):
            if ip not in BLOCK_TIME_ABS:
                continue
            drop_t = BLOCK_TIME_ABS[ip]
            if drop_t < full_index[0] or drop_t > full_index[-1]:
                continue
            color = ATTACKER_COLORS.get(ip, "#555555")
            ax.axvline(
                drop_t,
                color=color,
                linestyle=":",
                linewidth=1.8,
                alpha=0.95,
                zorder=4,
            )
            ax.text(
                drop_t,
                y_limit * label_offsets[idx % len(label_offsets)],
                f"{host_label(ip)}\nDROP",
                fontsize=8,
                fontweight="bold",
                color=color,
                ha="left",
                va="top",
                bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor=color, alpha=0.85),
                zorder=5,
            )

    ax.set_title(f"Packet/s per Host - Skenario {scenario_label}", loc="left", fontweight="bold")
    ax.set_xlabel("Waktu")
    ax.set_ylabel("Packet rate (pps)")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.tick_params(axis="x", rotation=20)
    ax.legend(loc="upper right", ncol=2, frameon=True, framealpha=0.92, fontsize=8)
    ax.set_axisbelow(True)

    note = "Catatan: dihitung dari jumlah paket per host per detik pada traffic_analysis.csv (rolling mean 5 detik)."
    if SCENARIO_HAS_DROP.get(scenario_label, False):
        note += " Garis putus-putus vertikal menandai waktu DROP_ICMP pada mitigation_events.csv."
    ax.text(
        0.0,
        -0.22,
        note,
        transform=ax.transAxes,
        fontsize=8.5,
        color="#555555",
        style="italic",
    )

    fname = f"packet_rate_per_host_{scenario_label.lower()}.png"
    savefig(fig, fname)


# ============================================================
# 5. P3 - CONFUSION MATRIX (dipertahankan)
# ============================================================

def confusion_counts(y_true: np.ndarray, y_pred: np.ndarray):
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    return np.array([[tn, fp], [fn, tp]]), accuracy, precision, recall, f1


def chart_P3_confusion_matrix():
    all_df = pd.concat([base, unmit, mit], ignore_index=True)

    all_df["ground_truth"] = (
        all_df["src_ip"].astype(str).isin(ATTACKERS) &
        (all_df["dst_ip"].astype(str) == VICTIM_IP) &
        (all_df["protocol_name"].astype(str).str.upper() == "ICMP") &
        (all_df["scenario"] != "Baseline")
    ).astype(int)

    y_true = all_df["ground_truth"].to_numpy(dtype=int)
    y_pred = all_df["final_prediction"].fillna(0).astype(int).to_numpy()

    cm, acc, prec, rec, f1 = confusion_counts(y_true, y_pred)
    total = cm.sum()
    cm_pct = (cm / total * 100) if total else np.zeros_like(cm, dtype=float)

    annot = np.array([
        [f"TN\n{cm[0,0]:,}\n({cm_pct[0,0]:.1f}%)", f"FP\n{cm[0,1]:,}\n({cm_pct[0,1]:.1f}%)"],
        [f"FN\n{cm[1,0]:,}\n({cm_pct[1,0]:.1f}%)", f"TP\n{cm[1,1]:,}\n({cm_pct[1,1]:.1f}%)"],
    ])

    fig, (ax, ax_metrics) = plt.subplots(
        1,
        2,
        figsize=(11.5, 6.2),
        gridspec_kw={"width_ratios": [3.2, 1.25]},
    )

    sns.heatmap(
        cm,
        annot=annot,
        fmt="",
        cmap="Blues",
        cbar=False,
        ax=ax,
        xticklabels=["Prediksi\nNORMAL", "Prediksi\nATTACK"],
        yticklabels=["Aktual\nNORMAL", "Aktual\nATTACK"],
        annot_kws={"fontsize": 12, "fontweight": "bold"},
        linewidths=1.5,
        linecolor="white",
        square=True,
    )
    ax.set_title("Confusion Matrix Deteksi ICMP Flood", fontweight="bold", pad=12)
    ax.set_xlabel("Prediksi Sistem")
    ax.set_ylabel("Ground Truth")

    ax_metrics.axis("off")
    metrics_text = (
        "Detection Metrics\n"
        "────────────────\n"
        f"Accuracy   : {acc:.3f}\n"
        f"Precision  : {prec:.3f}\n"
        f"Recall     : {rec:.3f}\n"
        f"F1-score   : {f1:.3f}\n\n"
        "Keterangan\n"
        "────────────────\n"
        "TP: Attack terdeteksi\n"
        "TN: Normal benar\n"
        "FP: False alarm\n"
        "FN: Attack terlewat"
    )
    ax_metrics.text(
        0.0,
        0.98,
        metrics_text,
        va="top",
        ha="left",
        fontsize=10,
        family="monospace",
        bbox=dict(boxstyle="round,pad=0.55", facecolor="#F8F9FA", edgecolor="#D6DBDF"),
    )

    fig.suptitle("P3 - Evaluasi Deteksi Controller Berdasarkan Gabungan 3 Skenario", fontsize=14, fontweight="bold", x=0.03, ha="left")
    fig.text(
        0.03,
        -0.02,
        "Ground truth: ICMP dari attacker IP ke victim pada skenario non-baseline = ATTACK. Prediksi: kolom final_prediction dari controller.",
        fontsize=8.5,
        color="#555555",
        style="italic",
    )

    savefig(fig, "P3_confusion_matrix_deteksi_icmp_flood.png")


# ============================================================
# 6. EKSEKUSI
# ============================================================

if __name__ == "__main__":
    print("\n[INFO] Membuat grafik CSV final untuk laporan...")

    for scenario_label in SCENARIOS:
        df_scenario = DATA_BY_SCENARIO[scenario_label]
        chart_pie_status_deteksi(df_scenario, scenario_label)
        chart_packet_rate_per_host(df_scenario, scenario_label)

    chart_P3_confusion_matrix()

    print(f"\n[SELESAI] Output tersimpan di: {OUT_DIR}")