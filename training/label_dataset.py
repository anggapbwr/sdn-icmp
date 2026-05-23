#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — Dataset Labeler (Ground Truth + Edge Cleanup)
"""

import os
import sys
import pandas as pd
from datetime import datetime

BASE_DIR = "/home/kali/sdn-icmp"
NORMAL_CSV = os.path.join(BASE_DIR, "data", "raw", "feature_dataset_normal.csv")
ATTACK_CSV = os.path.join(BASE_DIR, "data", "raw", "feature_dataset_attack.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "data", "processed", "feature_dataset_labeled.csv")

ATTACKER_IPS = {"10.0.0.1", "10.0.0.7", "10.0.0.13", "10.0.0.18"}
VICTIM_IP    = "10.0.0.25"

# Threshold untuk edge cleanup
# Attack dengan rate < ini dianggap edge effect (hping3 baru mulai/baru mati)
ATTACK_RATE_MIN_THRESHOLD = 5.0


def load_csv(path, label_hint):
    if not os.path.exists(path):
        print(f"[!] File tidak ditemukan: {path}")
        return None
    df = pd.read_csv(path)
    print(f"  [+] {label_hint:<8} loaded : {len(df):>6} rows from {os.path.basename(path)}")
    return df


def main():
    print("=" * 70)
    print("  DATASET LABELER — Ground Truth + Edge Cleanup")
    print(f"  Run time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    print("[*] Loading raw datasets...")
    df_normal = load_csv(NORMAL_CSV, "normal")
    df_attack = load_csv(ATTACK_CSV, "attack")

    if df_normal is None or df_attack is None:
        sys.exit(1)

    print("\n[*] Applying labeling rules...")

    # Rule 1: Sesi normal -> all label=0
    df_normal = df_normal.copy()
    df_normal["label"] = 0
    print(f"  Rule 1 (sesi normal -> all label=0): {len(df_normal):>6} rows")

    # Rule 2: Sesi attack -> label berdasarkan src_ip
    df_attack = df_attack.copy()
    df_attack["label"] = df_attack["src_ip"].apply(
        lambda ip: 1 if ip in ATTACKER_IPS else 0
    )

    n_attack_atk = (df_attack["label"] == 1).sum()
    n_attack_norm = (df_attack["label"] == 0).sum()
    print(f"  Rule 2a (sesi attack, src=attacker):   {n_attack_atk:>6} rows -> label=1")
    print(f"  Rule 2b (sesi attack, src=non-atkr):   {n_attack_norm:>6} rows -> label=0")

    # Rule 3: EDGE CLEANUP — drop attack rows dengan rate < threshold
    print(f"\n[*] Edge cleanup: drop attack rows dengan rate < {ATTACK_RATE_MIN_THRESHOLD} pps")
    print(f"  (Window awal/akhir hping3 yang belum/sudah berhenti)")

    n_before = (df_attack["label"] == 1).sum()
    edge_mask = (df_attack["label"] == 1) & (df_attack["packet_rate_ewma"] < ATTACK_RATE_MIN_THRESHOLD)
    n_edge = edge_mask.sum()
    df_attack = df_attack[~edge_mask].copy()
    n_after = (df_attack["label"] == 1).sum()
    print(f"  Before cleanup : {n_before:>6} attack rows")
    print(f"  Edge removed   : {n_edge:>6} rows")
    print(f"  After cleanup  : {n_after:>6} attack rows")

    # Merge
    df_all = pd.concat([df_normal, df_attack], ignore_index=True)
    print(f"\n[*] Total merged dataset: {len(df_all)} rows")

    # Final distribution
    print("\n[*] Final label distribution:")
    label_dist = df_all["label"].value_counts().sort_index()
    for lbl, count in label_dist.items():
        pct = count / len(df_all) * 100
        name = "NORMAL" if lbl == 0 else "ATTACK"
        print(f"  Label = {lbl} ({name}) : {count:>6} rows ({pct:.1f}%)")

    ratio = label_dist.min() / label_dist.max()
    print(f"\n  Balance ratio: {ratio:.2f}")

    # Rate distribution
    print("\n[*] Rate distribution per label:")
    for lbl in [0, 1]:
        sub = df_all[df_all["label"] == lbl]
        name = "NORMAL" if lbl == 0 else "ATTACK"
        rate = sub["packet_rate_ewma"]
        print(f"\n  {name}:")
        print(f"    min  : {rate.min():>10.2f} pps")
        print(f"    p25  : {rate.quantile(0.25):>10.2f} pps")
        print(f"    p50  : {rate.median():>10.2f} pps")
        print(f"    p75  : {rate.quantile(0.75):>10.2f} pps")
        print(f"    max  : {rate.max():>10.2f} pps")

    # Overlap analysis (after filter)
    df_scope = df_all[df_all["is_to_victim"] == 1].copy()
    print(f"\n[*] After is_to_victim=1 filter: {len(df_scope)} rows")

    normal_max = df_scope[df_scope["label"] == 0]["packet_rate_ewma"].max()
    attack_min = df_scope[df_scope["label"] == 1]["packet_rate_ewma"].min()

    print(f"\n[*] Overlap analysis (scope filtered):")
    print(f"  Normal max rate : {normal_max:.2f} pps")
    print(f"  Attack min rate : {attack_min:.2f} pps")

    overlap = df_scope[
        (df_scope["packet_rate_ewma"] >= 10) &
        (df_scope["packet_rate_ewma"] <= 200)
    ]
    n_norm_in = (overlap["label"] == 0).sum()
    n_atk_in = (overlap["label"] == 1).sum()
    print(f"\n  Overlap zone [10-200 pps]:")
    print(f"    Normal in zone : {n_norm_in}")
    print(f"    Attack in zone : {n_atk_in}")

    if n_atk_in > 0:
        print(f"\n  ✅ SVM punya {n_atk_in} kasus attack di overlap zone")
        print(f"     dengan {n_norm_in} normal di zona yang sama.")
        print(f"     SVM harus belajar pisahkan via inter_arrival_std.")
    else:
        print(f"\n  ⚠️  Tidak ada attack di overlap zone. Threshold akan sangat unggul.")

    # Save
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df_all.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[+] Saved to: {OUTPUT_CSV}")

    print("\nNext step: python3 training/svm_train.py")


if __name__ == "__main__":
    main()
