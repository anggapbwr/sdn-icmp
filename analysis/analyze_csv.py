#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — CSV Forensic Analyzer (Gabungan 3 Skenario)
==============================================================
Membaca traffic_analysis.csv + mitigation_events.csv dari 3 skenario:
baseline, ddos_unmitigated, ddos (mitigated). Menggantikan analyze_baseline.py,
analyze_ddos.py, dan bagian CSV dari analyze_combined.py.

Output:
  - logs/report_graphs/csv/G1_packet_rate_baseline.png
  - logs/report_graphs/csv/G2_detection_status_3way.png
  - logs/report_graphs/csv/G3_gantt_mitigated_vs_unmitigated.png
  - logs/report_graphs/csv/G4_selectivity_mitigated.png
  - logs/report_graphs/csv/G8_confusion_matrix.png
  - logs/report_graphs/csv/csv_summary.md

Usage:
  python3 analysis/analyze_csv.py
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

SCENARIOS = {
    "baseline":          f"{BASE_DIR}/logs/archive/baseline",
    "ddos_unmitigated":  f"{BASE_DIR}/logs/archive/ddos_unmitigated",
    "ddos":              f"{BASE_DIR}/logs/archive/ddos",
}
OUTPUT_DIR = f"{BASE_DIR}/logs/report_graphs/csv"
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

SCENARIO_LABELS = {
    "baseline":         "Baseline",
    "ddos_unmitigated": "DDoS Tanpa Mitigasi",
    "ddos":             "DDoS Dengan Mitigasi",
}

# ─── Style ────────────────────────────────────────────────────────────────────

PALETTE = {
    "baseline":  "#4A90D9",
    "unmit":     "#E05C5C",
    "mit":       "#27AE60",
    "normal":    "#4A90D9",
    "warning":   "#F5A623",
    "confirmed": "#C0392B",
    "drop":      "#8E44AD",
    "tp":        "#27AE60",
    "fp":        "#E05C5C",
    "fn":        "#E05C5C",
    "tn":        "#4A90D9",
    "text":      "#2C3E50",
    "sub":       "#7F8C8D",
    "grid":      "#ECEFF1",
}

STATE_COLORS = {
    "NORMAL":           PALETTE["normal"],
    "WARNING":          PALETTE["warning"],
    "ATTACK_CONFIRMED": PALETTE["confirmed"],
    "DROP_ACTIVE":      PALETTE["drop"],
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

def prep_traffic(df):
    """Sesuai skema 13 kolom: timestamp,src_ip,dst_ip,protocol_name,session_id,
    detection_status,phase,packet_rate,packet_count,threat_score,
    final_prediction,dpid_name,event_note"""
    if df.empty:
        return df
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["packet_rate", "threat_score", "packet_count", "final_prediction"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in ["src_ip", "dst_ip", "protocol_name", "detection_status",
                "phase", "dpid_name", "event_note"]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()
    return df

def prep_mitigation(df):
    if df.empty:
        return df
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["src_ip", "dpid_name", "action", "reason"]:
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

# ─── Load semua skenario ───────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  SDN CSV FORENSIC ANALYZER — 3 SKENARIO")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

data = {}
for key, folder in SCENARIOS.items():
    print(f"\n[*] Loading {SCENARIO_LABELS[key]} ...")
    traffic = prep_traffic(load_csv(os.path.join(folder, "traffic_analysis.csv")))
    mit     = prep_mitigation(load_csv(os.path.join(folder, "mitigation_events.csv")))
    print(f"  [i] traffic_analysis.csv : {len(traffic):,} events")
    print(f"  [i] mitigation_events.csv: {len(mit):,} events")
    data[key] = {"traffic": traffic, "mitigation": mit}

if data["baseline"]["traffic"].empty or data["ddos"]["traffic"].empty:
    print("\n  [!] Baseline atau DDoS (mitigated) CSV kosong. Tidak bisa lanjut.")
    sys.exit(1)

# ─── Statistik ringkas per skenario ────────────────────────────────────────────

def calc_stats(df):
    if df.empty:
        return {"total": 0, "duration": 0, "states": {}, "avg_rate": 0, "max_rate": 0}
    duration = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
    states   = df["detection_status"].value_counts().to_dict()
    return {
        "total":    len(df),
        "duration": duration,
        "states":   states,
        "avg_rate": float(df["packet_rate"].mean()) if "packet_rate" in df.columns else 0,
        "max_rate": float(df["packet_rate"].max())  if "packet_rate" in df.columns else 0,
    }

stats = {k: calc_stats(v["traffic"]) for k, v in data.items()}

print("\n[*] Ringkasan statistik:")
for k in SCENARIOS:
    s = stats[k]
    print(f"    {SCENARIO_LABELS[k]:<24}: {s['total']:>7,} events | "
          f"{s['duration']:>7.1f}s | avg {s['avg_rate']:>6.2f} pps | max {s['max_rate']:>7.2f} pps")

# Mitigation timestamps (khusus skenario ddos/mitigated)
mitigation_times = {}
mit_df = data["ddos"]["mitigation"]
if not mit_df.empty and "action" in mit_df.columns:
    drop_rows = mit_df[mit_df["action"].str.contains("DROP_ICMP", na=False)]
    for ip, grp in drop_rows.groupby("src_ip"):
        mitigation_times[ip] = grp["timestamp"].min()

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 1 — Packet Rate Timeline Baseline
# ════════════════════════════════════════════════════════════════════════════

def graph_1():
    fn = "G1_packet_rate_baseline.png"
    df = data["baseline"]["traffic"]
    if df.empty:
        print(f"  [!] Skip {fn}: baseline kosong"); return

    fig, ax = plt.subplots(figsize=(15, 6))

    for proto in sorted(df["protocol_name"].unique()):
        sub = df[df["protocol_name"] == proto].dropna(
            subset=["timestamp", "packet_rate"]).sort_values("timestamp")
        if sub.empty:
            continue
        sub = sub.set_index("timestamp")
        rate_binned = sub["packet_rate"].resample("2S").mean().fillna(0)
        if rate_binned.empty:
            continue
        ax.plot(rate_binned.index, rate_binned.values,
                linewidth=1.6, alpha=0.85, label=proto, marker="o", markersize=3)

    ax.axhline(WARNING_PPS, color=PALETTE["warning"], linestyle="--",
               linewidth=1, alpha=0.6, label=f"Warning threshold ({WARNING_PPS} pps)")

    ax.set_title("Skenario Baseline — Packet Rate Timeline per Protokol")
    subtitle(ax, "Rate stabil & rendah sepanjang sesi, jauh di bawah threshold — bukti network sehat")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Packet Rate (pps)")
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper right", title="Protocol")
    ax.set_axisbelow(True)
    save(fn)

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 2 — Distribusi Status Deteksi, 3 Skenario Berdampingan
# ════════════════════════════════════════════════════════════════════════════

def graph_2():
    fn = "G2_detection_status_3way.png"
    order = ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "DROP_ACTIVE"]

    fig, ax = plt.subplots(figsize=(15, 7))
    x = np.arange(len(order))
    width = 0.26
    offsets = [-width, 0, width]
    colors = [PALETTE["baseline"], PALETTE["unmit"], PALETTE["mit"]]

    for i, key in enumerate(SCENARIOS):
        counts = [stats[key]["states"].get(s, 0) for s in order]
        bars = ax.bar(x + offsets[i], counts, width, color=colors[i],
                      label=SCENARIO_LABELS[key], edgecolor="white",
                      linewidth=1.1, zorder=3)
        for bar, val in zip(bars, counts):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                        f"{val:,}", ha="center", va="bottom",
                        fontsize=8, fontweight="bold", color=PALETTE["text"],
                        rotation=0)

    ax.set_xticks(x)
    ax.set_xticklabels(order)
    ax.set_title("Distribusi Status Deteksi — Perbandingan 3 Skenario")
    subtitle(ax, "Baseline: 100% NORMAL | Unmitigated: terus di ATTACK_CONFIRMED | Mitigated: berujung DROP_ACTIVE")
    ax.set_ylabel("Jumlah Events")
    ax.legend()
    ax.set_axisbelow(True)
    save(fn)

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 3 — Gantt Dual Panel: Mitigated vs Unmitigated
# ════════════════════════════════════════════════════════════════════════════

def _per_attacker_timeline(df, mit_times):
    """Hitung first_seen, first_warn, first_conf, drop_time, last_seen per attacker."""
    result = {}
    for ip in ATTACKER_IPS:
        grp = df[
            (df["src_ip"] == ip) &
            (df["dst_ip"] == VICTIM_IP) &
            (df["protocol_name"] == "ICMP")
        ]
        if grp.empty:
            result[ip] = None
            continue
        first_seen = grp["timestamp"].min()
        last_seen  = grp["timestamp"].max()
        w = grp[grp["detection_status"] == "WARNING"]["timestamp"]
        c = grp[grp["detection_status"] == "ATTACK_CONFIRMED"]["timestamp"]
        first_warn = w.min() if not w.empty else pd.NaT
        first_conf = c.min() if not c.empty else pd.NaT
        drop_t     = mit_times.get(ip, pd.NaT)
        result[ip] = {
            "first_seen": first_seen, "last_seen": last_seen,
            "first_warn": first_warn, "first_conf": first_conf,
            "drop_time":  drop_t,
        }
    return result

def _draw_gantt(ax, timeline, title):
    yticks, ylabels = [], []
    y = 0
    for idx, ip in enumerate(ATTACKER_IPS):
        s = timeline.get(ip)
        if s is None:
            continue
        color = ATTACKER_COLORS[idx]
        fs, fw, fc, dt, ls = (s["first_seen"], s["first_warn"],
                              s["first_conf"], s["drop_time"], s["last_seen"])

        if not pd.isna(fw) and not pd.isna(fs):
            dur = (fw - fs).total_seconds()
            if dur > 0:
                ax.barh(y, dur, left=fs, height=0.55, color=PALETTE["normal"],
                        alpha=0.75, edgecolor="white", linewidth=1)
        if not pd.isna(fw) and not pd.isna(fc):
            dur = (fc - fw).total_seconds()
            if dur > 0:
                ax.barh(y, dur, left=fw, height=0.55, color=PALETTE["warning"],
                        alpha=0.85, edgecolor="white", linewidth=1)
        if not pd.isna(fc):
            end_attack = dt if not pd.isna(dt) else ls
            if not pd.isna(end_attack):
                dur = (end_attack - fc).total_seconds()
                if dur > 0:
                    ax.barh(y, dur, left=fc, height=0.55, color=PALETTE["confirmed"],
                            alpha=0.9, edgecolor="white", linewidth=1)
        if not pd.isna(dt):
            end_t = ls if (not pd.isna(ls) and ls > dt) else dt + pd.Timedelta(seconds=10)
            dur = (end_t - dt).total_seconds()
            if dur > 0:
                ax.barh(y, dur, left=dt, height=0.55, color=PALETTE["drop"],
                        alpha=0.85, edgecolor="white", linewidth=1)
            ax.scatter(dt, y, s=110, marker="v", color="black", zorder=10,
                       edgecolor="white", linewidth=1.4)

        yticks.append(y)
        ylabels.append(attacker_label(ip))
        y += 1

    ax.set_yticks(yticks)
    ax.set_yticklabels(ylabels, fontsize=9)
    ax.set_title(title)
    ax.tick_params(axis="x", rotation=25)
    ax.set_axisbelow(True)
    ax.grid(axis="y", alpha=0.3)

def graph_3():
    fn = "G3_gantt_mitigated_vs_unmitigated.png"

    tl_mit   = _per_attacker_timeline(data["ddos"]["traffic"], mitigation_times)
    tl_unmit = _per_attacker_timeline(data["ddos_unmitigated"]["traffic"], {})

    fig, axes = plt.subplots(2, 1, figsize=(15, 10), sharex=False)

    _draw_gantt(axes[0], tl_mit, "Skenario DDoS DENGAN Mitigasi")
    _draw_gantt(axes[1], tl_unmit, "Skenario DDoS TANPA Mitigasi")
    axes[1].set_xlabel("Timestamp")

    legend_handles = [
        mpatches.Patch(color=PALETTE["normal"],    alpha=0.75, label="NORMAL"),
        mpatches.Patch(color=PALETTE["warning"],   alpha=0.85, label="WARNING"),
        mpatches.Patch(color=PALETTE["confirmed"], alpha=0.90, label="ATTACK_CONFIRMED"),
        mpatches.Patch(color=PALETTE["drop"],      alpha=0.85, label="DROP_ACTIVE"),
    ]
    fig.legend(handles=legend_handles, loc="upper center", ncol=4,
               bbox_to_anchor=(0.5, 1.02), fontsize=9)

    fig.suptitle("Perbandingan Lifecycle Deteksi: Dengan vs Tanpa Mitigasi",
                 fontsize=14, fontweight="bold", y=1.06)
    fig.text(0.01, 1.0, "▼ = waktu DROP rule terpasang. Panel bawah tidak pernah "
             "mencapai DROP_ACTIVE — serangan berlangsung terus tanpa dihentikan.",
             fontsize=8, color=PALETTE["sub"])
    save(fn)

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 4 — Selektivitas Mitigasi (Skenario Mitigated)
# ════════════════════════════════════════════════════════════════════════════

def graph_4():
    fn = "G4_selectivity_mitigated.png"
    df = data["ddos"]["traffic"]
    if df.empty:
        print(f"  [!] Skip {fn}: data ddos kosong"); return

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

    fig, ax = plt.subplots(figsize=(15, 7))

    if not attack_df.empty:
        atk = attack_df.dropna(subset=["timestamp", "packet_rate"]).set_index("timestamp")
        atk_rate = atk["packet_rate"].resample("2S").sum().fillna(0)
        if not atk_rate.empty:
            ax.plot(atk_rate.index, atk_rate.values, color=PALETTE["unmit"],
                    linewidth=2.2, alpha=0.9, label="Attacker traffic (4 hosts → victim)",
                    marker="o", markersize=3)
            ax.fill_between(atk_rate.index, atk_rate.values, 0,
                            color=PALETTE["unmit"], alpha=0.12)

    if not baseline_df.empty:
        bsl = baseline_df.dropna(subset=["timestamp", "packet_rate"]).set_index("timestamp")
        bsl_rate = bsl["packet_rate"].resample("2S").sum().fillna(0)
        if not bsl_rate.empty:
            ax.plot(bsl_rate.index, bsl_rate.values, color=PALETTE["mit"],
                    linewidth=2.0, alpha=0.9, label="Baseline traffic (normal hosts → victim)",
                    marker="s", markersize=3)
            ax.fill_between(bsl_rate.index, bsl_rate.values, 0,
                            color=PALETTE["mit"], alpha=0.12)

    for ip, t in mitigation_times.items():
        ax.axvline(t, color=PALETTE["drop"], linestyle=":", linewidth=1.5, alpha=0.6)

    ax.set_title("Selektivitas Mitigasi: Attacker vs Baseline Traffic menuju Victim")
    subtitle(ax, "Attacker turun ke 0 setelah DROP aktif — baseline tetap mengalir = mitigasi src-IP specific")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Aggregated Packet Rate (pps)")
    ax.tick_params(axis="x", rotation=30)
    ax.legend(loc="upper right")
    ax.set_axisbelow(True)
    save(fn)

# ════════════════════════════════════════════════════════════════════════════
# GRAFIK 8 — Confusion Matrix Operasional
# ════════════════════════════════════════════════════════════════════════════

def _ground_truth_and_pred(df):
    """Ground truth: ICMP attacker->victim = 1 (attack), sisanya 0.
    Prediksi sistem: detection_status != NORMAL -> 1, NORMAL -> 0."""
    if df.empty:
        return np.array([]), np.array([])
    gt = (
        df["src_ip"].isin(ATTACKER_IPS) &
        (df["dst_ip"] == VICTIM_IP) &
        (df["protocol_name"] == "ICMP")
    ).astype(int).values
    pred = (df["detection_status"] != "NORMAL").astype(int).values
    return gt, pred

def graph_8():
    fn = "G8_confusion_matrix.png"

    gts, preds = [], []
    for key in SCENARIOS:
        gt, pred = _ground_truth_and_pred(data[key]["traffic"])
        gts.append(gt)
        preds.append(pred)
    gt_all   = np.concatenate(gts)
    pred_all = np.concatenate(preds)

    if len(gt_all) == 0:
        print(f"  [!] Skip {fn}: tidak ada data"); return

    tp = int(np.sum((gt_all == 1) & (pred_all == 1)))
    fn_ = int(np.sum((gt_all == 1) & (pred_all == 0)))
    fp = int(np.sum((gt_all == 0) & (pred_all == 1)))
    tn = int(np.sum((gt_all == 0) & (pred_all == 0)))

    total = tp + fn_ + fp + tn
    accuracy  = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn_) if (tp + fn_) else 0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    matrix = np.array([[tn, fp], [fn_, tp]])

    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(matrix, cmap="Blues", vmin=0)

    labels = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            val = matrix[i, j]
            txt_color = "white" if val > matrix.max() * 0.5 else PALETTE["text"]
            ax.text(j, i, f"{labels[i][j]}\n{val:,}", ha="center", va="center",
                    fontsize=15, fontweight="bold", color=txt_color)

    ax.set_xticks([0, 1]); ax.set_xticklabels(["Diprediksi NORMAL", "Diprediksi TERDETEKSI"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Aktual NORMAL", "Aktual ATTACK"])
    ax.set_title("Confusion Matrix Operasional — Sistem Deteksi (3 Skenario Gabungan)")
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)

    metric_text = (
        f"Accuracy: {accuracy:.4f}   |   Precision: {precision:.4f}   |   "
        f"Recall: {recall:.4f}   |   F1-Score: {f1:.4f}"
    )
    fig.text(0.5, -0.02, metric_text, ha="center", fontsize=10,
             color=PALETTE["text"], fontweight="bold")
    subtitle(ax, "Ground truth: traffic ICMP attacker\u2192victim = ATTACK; Prediksi: detection_status \u2260 NORMAL")
    save(fn)

    return {"tp": tp, "fp": fp, "fn": fn_, "tn": tn,
            "accuracy": accuracy, "precision": precision,
            "recall": recall, "f1": f1}

# ─── Jalankan semua grafik ──────────────────────────────────────────────────

print("\n[*] Generating CSV-based graphs ...")
graph_1()
graph_2()
graph_3()
graph_4()
cm_result = graph_8()

# ─── Markdown report ──────────────────────────────────────────────────────────

print("\n[*] Writing csv_summary.md ...")
md_path = out("csv_summary.md")
NOW = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

scenario_rows = []
for key in SCENARIOS:
    s = stats[key]
    scenario_rows.append(
        f"| {SCENARIO_LABELS[key]} | {s['total']:,} | {s['duration']:.1f}s | "
        f"{s['avg_rate']:.2f} pps | {s['max_rate']:.2f} pps |"
    )

state_rows = []
order = ["NORMAL", "WARNING", "ATTACK_CONFIRMED", "DROP_ACTIVE"]
for st in order:
    row = f"| {st} "
    for key in SCENARIOS:
        row += f"| {stats[key]['states'].get(st, 0):,} "
    row += "|"
    state_rows.append(row)

mit_rows = []
if not mit_df.empty:
    for _, row in mit_df.iterrows():
        mit_rows.append(
            f"| {fmt_ts(row.get('timestamp'))} | `{row.get('src_ip','')}` | "
            f"{row.get('dpid_name','')} | {row.get('action','')} |"
        )

cm_section = ""
if cm_result:
    cm_section = f"""
## 4. Confusion Matrix Operasional

Dihitung dari gabungan event ketiga skenario, membandingkan ground truth
(traffic ICMP attacker→victim = ATTACK) dengan prediksi sistem
(`detection_status` ≠ NORMAL = terdeteksi).

| | Diprediksi NORMAL | Diprediksi TERDETEKSI |
|---|---:|---:|
| **Aktual NORMAL** | TN = {cm_result['tn']:,} | FP = {cm_result['fp']:,} |
| **Aktual ATTACK** | FN = {cm_result['fn']:,} | TP = {cm_result['tp']:,} |

- Accuracy: **{cm_result['accuracy']:.4f}**
- Precision: **{cm_result['precision']:.4f}**
- Recall: **{cm_result['recall']:.4f}**
- F1-Score: **{cm_result['f1']:.4f}**

![Confusion Matrix](G8_confusion_matrix.png)
"""

md_content = f"""# CSV Forensic Analysis — 3 Skenario

**Generated:** {NOW}
**Data source:** `traffic_analysis.csv` + `mitigation_events.csv` (baseline, ddos_unmitigated, ddos)

---

## 1. Ringkasan Eksperimen

| Skenario | Total Events | Durasi | Avg Rate | Max Rate |
|----------|-------------:|-------:|---------:|---------:|
{chr(10).join(scenario_rows)}

---

## 2. Distribusi Status Deteksi

| Status | {SCENARIO_LABELS['baseline']} | {SCENARIO_LABELS['ddos_unmitigated']} | {SCENARIO_LABELS['ddos']} |
|--------|---:|---:|---:|
{chr(10).join(state_rows)}

![Distribusi Status 3 Skenario](G2_detection_status_3way.png)

---

## 3. Lifecycle Deteksi & Mitigasi

![Gantt Mitigated vs Unmitigated](G3_gantt_mitigated_vs_unmitigated.png)

Pada skenario tanpa mitigasi, seluruh attacker bertahan di status ATTACK_CONFIRMED
hingga akhir sesi observasi — tidak pernah mencapai DROP_ACTIVE. Pada skenario
dengan mitigasi, keempat attacker berhasil mencapai DROP_ACTIVE secara bertahap.

![Packet Rate Baseline](G1_packet_rate_baseline.png)

![Selektivitas Mitigasi](G4_selectivity_mitigated.png)

---

## 4. Mitigation Events (Skenario Mitigated)

| Time | Source IP | Switch | Action |
|------|-----------|--------|--------|
{chr(10).join(mit_rows) if mit_rows else "| (tidak ada event) |"}

{cm_section}

---

*Di-generate otomatis oleh `analyze_csv.py`. Untuk analisis PCAP, lihat `pcap_summary.md`.*
"""

with open(md_path, "w", encoding="utf-8") as f:
    f.write(md_content)
print(f"  [+] csv_summary.md")

print(f"\n{'='*60}")
print(f"  CSV ANALYSIS DONE — Output: {OUTPUT_DIR}")
print(f"{'='*60}\n")
