#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

import matplotlib.pyplot as plt
import pandas as pd

CSV_FILE = "traffic_analysis.csv"
OUTPUT_FILE = "unmitigated_packet_rate_per_attacker.png"
VICTIM_IP = "10.0.0.25"

ATTACKERS = {
    "10.0.0.1": "h1",
    "10.0.0.7": "h7",
    "10.0.0.13": "h13",
    "10.0.0.18": "h18",
}


def main():
    try:
        data = pd.read_csv(CSV_FILE)
    except FileNotFoundError:
        print(f"[ERROR] Berkas tidak ditemukan: {CSV_FILE}")
        sys.exit(1)
    except Exception as error:
        print(f"[ERROR] Gagal membaca CSV: {error}")
        sys.exit(1)

    required_columns = {
        "timestamp",
        "src_ip",
        "dst_ip",
        "protocol_name",
        "packet_rate",
    }

    missing_columns = required_columns.difference(data.columns)

    if missing_columns:
        print(
            "[ERROR] Kolom tidak ditemukan: "
            + ", ".join(sorted(missing_columns))
        )
        sys.exit(1)

    data["timestamp"] = pd.to_datetime(
        data["timestamp"],
        errors="coerce",
    )

    data["packet_rate"] = pd.to_numeric(
        data["packet_rate"],
        errors="coerce",
    )

    filtered = data[
        data["src_ip"].isin(ATTACKERS)
        & (data["dst_ip"] == VICTIM_IP)
        & (data["protocol_name"].str.upper() == "ICMP")
    ].copy()

    filtered = filtered.dropna(
        subset=["timestamp", "packet_rate"],
    )

    if filtered.empty:
        print("[ERROR] Data attacker tidak ditemukan.")
        sys.exit(1)

    start_time = filtered["timestamp"].min()

    filtered["elapsed_second"] = (
        filtered["timestamp"] - start_time
    ).dt.total_seconds().astype(int)

    # Nilai maksimum setiap detik digunakan agar grafik tidak terlalu padat.
    per_second = (
        filtered.groupby(
            ["elapsed_second", "src_ip"],
            as_index=False,
        )["packet_rate"]
        .max()
    )

    plt.figure(figsize=(12, 6))

    for attacker_ip, hostname in ATTACKERS.items():
        attacker_data = per_second[
            per_second["src_ip"] == attacker_ip
        ]

        if attacker_data.empty:
            continue

        plt.plot(
            attacker_data["elapsed_second"],
            attacker_data["packet_rate"],
            label=f"{hostname} ({attacker_ip})",
        )

    plt.axhline(
        y=10,
        linestyle="--",
        linewidth=1,
        label="Ambang WARNING 10 pps",
    )

    plt.axhline(
        y=25,
        linestyle="--",
        linewidth=1,
        label="Ambang ATTACK_CONFIRMED 25 pps",
    )

    plt.xlabel("Waktu sejak aktivitas attacker tercatat (detik)")
    plt.ylabel("Packet Rate (pps)")
    plt.title(
        "Packet Rate per Attacker pada Skenario DDoS tanpa Mitigasi"
    )
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUTPUT_FILE, dpi=300)
    plt.close()

    print(f"[OK] Grafik disimpan: {OUTPUT_FILE}")
    print(f"[INFO] Jumlah data setelah filter: {len(filtered)} event")
    print(
        f"[INFO] Rentang waktu: "
        f"{per_second['elapsed_second'].min()}–"
        f"{per_second['elapsed_second'].max()} detik"
    )

    print("\nPuncak packet rate per attacker:")

    for attacker_ip, hostname in ATTACKERS.items():
        attacker_data = per_second[
            per_second["src_ip"] == attacker_ip
        ]

        if attacker_data.empty:
            print(f"  {hostname}: tidak ditemukan")
            continue

        peak_index = attacker_data["packet_rate"].idxmax()
        peak_row = attacker_data.loc[peak_index]

        print(
            f"  {hostname} ({attacker_ip}): "
            f"{peak_row['packet_rate']:.2f} pps "
            f"pada detik ke-{int(peak_row['elapsed_second'])}"
        )


if __name__ == "__main__":
    main()
