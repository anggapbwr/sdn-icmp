#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyzer final untuk tiga skenario pengujian SDN ICMP Flood:

1. baseline
2. ddos_unmitigated
3. ddos_mitigated

Jalankan dari mana saja:
    python3 /home/kali/sdn-icmp/analyze_scenarios.py

Data yang dibaca:
    logs/archive/<scenario>/traffic_analysis.csv
    logs/archive/<scenario>/mitigation_events.csv
    logs/archive/<scenario>/*.pcap

Output ringkasan:
    logs/charts/scenario_analysis_summary.csv
    logs/charts/attacker_timing_summary.csv

Catatan:
- Jumlah record CSV tidak sama dengan jumlah paket jaringan.
- Jumlah paket, durasi capture, dan average packet rate diambil dari PCAP
  menggunakan tshark apabila tersedia.
"""

import csv
import os
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# ============================================================================
# KONFIGURASI
# ============================================================================

BASE_DIR = Path(os.environ.get("SDN_ICMP_BASE_DIR", "/home/kali/sdn-icmp"))
ARCHIVE_DIR = BASE_DIR / "logs" / "archive"
OUTPUT_DIR = BASE_DIR / "logs" / "charts"

ATTACKER_IPS = [
    "10.0.0.1",
    "10.0.0.7",
    "10.0.0.13",
    "10.0.0.18",
]
VICTIM_IP = "10.0.0.25"

ATTACK_STATUS = "ATTACK_CONFIRMED"
DROP_ACTION = "DROP_ICMP"

DETECTION_THRESHOLD_PPS = 25.0
MITIGATION_DELAY_TARGET_SECONDS = 8.0
MITIGATION_DELAY_TOLERANCE_SECONDS = 1.0

SCENARIOS = {
    "baseline": {
        "label": "SKENARIO 1 — BASELINE",
        "pcaps": [
            ("primary", "network_baseline.pcap"),
        ],
    },
    "ddos_unmitigated": {
        "label": "SKENARIO 2 — DDoS TANPA MITIGASI",
        "pcaps": [
            ("primary", "network_ddos_unmitigated.pcap"),
        ],
    },
    "ddos_mitigated": {
        "label": "SKENARIO 3 — DDoS DENGAN MITIGASI",
        "pcaps": [
            ("primary", "network_ddos_mitigated.pcap"),
            ("supplemental_clean", "network_ddos_mitigated_clean.pcap"),
        ],
    },
}

REQUIRED_TRAFFIC_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol_name",
    "session_id",
    "detection_status",
    "phase",
    "packet_rate",
    "packet_count",
    "threat_score",
    "dpid_name",
    "event_note",
}

REQUIRED_MITIGATION_COLUMNS = {
    "timestamp",
    "src_ip",
    "action",
}


# ============================================================================
# UTILITAS
# ============================================================================

def section(title: str) -> None:
    print()
    print("=" * 100)
    print(f"  {title}")
    print("=" * 100)


def subsection(title: str) -> None:
    print()
    print(f"  {title}")
    print("  " + "-" * max(20, len(title)))


def pass_label(ok: bool) -> str:
    return "PASS" if ok else "CEK ULANG"


def safe_float(value: object) -> Optional[float]:
    try:
        text = str(value).strip()
        if not text:
            return None
        return float(text)
    except (TypeError, ValueError):
        return None


def safe_int(value: object) -> Optional[int]:
    number = safe_float(value)
    if number is None:
        return None
    return int(number)


def parse_ts(value: object) -> Optional[datetime]:
    text = str(value).strip()
    if not text:
        return None

    formats = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )

    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def format_ts(value: Optional[datetime]) -> str:
    if value is None:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")


def human_size(size_bytes: Optional[int]) -> str:
    if size_bytes is None:
        return "-"

    value = float(size_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def duration_from_rows(rows: Iterable[dict]) -> Tuple[Optional[datetime], Optional[datetime], float]:
    timestamps = []
    for row in rows:
        ts = parse_ts(row.get("timestamp", ""))
        if ts is not None:
            timestamps.append(ts)

    if not timestamps:
        return None, None, 0.0

    start = min(timestamps)
    end = max(timestamps)
    return start, end, max(0.0, (end - start).total_seconds())


def first_row_by_time(rows: Iterable[dict], predicate) -> Optional[dict]:
    matches = []
    for row in rows:
        if not predicate(row):
            continue
        ts = parse_ts(row.get("timestamp", ""))
        if ts is not None:
            matches.append((ts, row))

    if not matches:
        return None

    matches.sort(key=lambda item: item[0])
    return matches[0][1]


def first_rows_per_attacker(rows: Iterable[dict], predicate) -> Dict[str, dict]:
    result: Dict[str, Tuple[datetime, dict]] = {}

    for row in rows:
        ip = row.get("src_ip", "").strip()
        if ip not in ATTACKER_IPS or not predicate(row):
            continue

        ts = parse_ts(row.get("timestamp", ""))
        if ts is None:
            continue

        if ip not in result or ts < result[ip][0]:
            result[ip] = (ts, row)

    return {ip: item[1] for ip, item in result.items()}


def write_csv(path: Path, fieldnames: List[str], rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ============================================================================
# PEMBACAAN CSV
# ============================================================================

def load_dict_csv(path: Path, required_columns: set) -> Optional[List[dict]]:
    """
    Return:
      None -> file tidak ditemukan / tidak dapat dibaca / header tidak valid
      []   -> file valid, tetapi hanya berisi header
      list -> record data
    """
    if not path.exists():
        print(f"  [!] File tidak ditemukan: {path}")
        return None

    try:
        with path.open("r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)

            if reader.fieldnames is None:
                print(f"  [!] CSV tidak memiliki header: {path}")
                return None

            normalized_header = {
                str(column).strip()
                for column in reader.fieldnames
                if column is not None
            }

            missing = required_columns - normalized_header
            if missing:
                print(f"  [!] Header CSV tidak lengkap: {path}")
                print(f"      Kolom yang hilang: {sorted(missing)}")
                print(f"      Header terbaca   : {sorted(normalized_header)}")
                return None

            rows: List[dict] = []
            for line_number, raw_row in enumerate(reader, start=2):
                row = {
                    str(key).strip(): (value or "").strip()
                    for key, value in raw_row.items()
                    if key is not None
                }

                if not any(row.values()):
                    continue

                if parse_ts(row.get("timestamp", "")) is None:
                    print(
                        f"  [!] Baris {line_number} dilewati karena timestamp tidak valid: "
                        f"{row.get('timestamp', '')!r}"
                    )
                    continue

                rows.append(row)

            return rows

    except (OSError, csv.Error) as exc:
        print(f"  [!] Gagal membaca {path}: {exc}")
        return None


def load_traffic_csv(path: Path) -> Optional[List[dict]]:
    return load_dict_csv(path, REQUIRED_TRAFFIC_COLUMNS)


def load_mitigation_csv(path: Path) -> Optional[List[dict]]:
    return load_dict_csv(path, REQUIRED_MITIGATION_COLUMNS)


# ============================================================================
# PEMBACAAN PCAP
# ============================================================================

def inspect_pcap(path: Path) -> dict:
    result = {
        "path": str(path),
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else None,
        "packet_count": None,
        "start_epoch": None,
        "end_epoch": None,
        "duration_seconds": None,
        "average_pps": None,
        "tshark_used": False,
        "error": "",
    }

    if not path.exists():
        result["error"] = "file tidak ditemukan"
        return result

    tshark = shutil.which("tshark")
    if tshark is None:
        result["error"] = "tshark tidak ditemukan; hanya ukuran file yang dapat dibaca"
        return result

    command = [
        tshark,
        "-n",
        "-r",
        str(path),
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
    ]

    count = 0
    first_epoch: Optional[float] = None
    last_epoch: Optional[float] = None

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        assert process.stdout is not None
        for line in process.stdout:
            epoch = safe_float(line.strip())
            if epoch is None:
                continue

            count += 1
            if first_epoch is None:
                first_epoch = epoch
            last_epoch = epoch

        stderr_text = ""
        if process.stderr is not None:
            stderr_text = process.stderr.read().strip()

        return_code = process.wait()
        if return_code != 0:
            result["error"] = stderr_text or f"tshark exit code {return_code}"
            return result

        duration = 0.0
        if first_epoch is not None and last_epoch is not None:
            duration = max(0.0, last_epoch - first_epoch)

        result.update(
            {
                "packet_count": count,
                "start_epoch": first_epoch,
                "end_epoch": last_epoch,
                "duration_seconds": duration,
                "average_pps": (count / duration) if duration > 0 else None,
                "tshark_used": True,
                "error": stderr_text,
            }
        )
        return result

    except OSError as exc:
        result["error"] = str(exc)
        return result


# ============================================================================
# RINGKASAN DATA
# ============================================================================

def summarize_scenario(
    scenario: str,
    traffic_rows: Optional[List[dict]],
    mitigation_rows: Optional[List[dict]],
    pcap_results: Dict[str, dict],
) -> dict:
    rows = traffic_rows or []
    mitigation = mitigation_rows or []

    start, end, duration = duration_from_rows(rows)
    statuses = Counter(row.get("detection_status", "") for row in rows)

    drop_rows = [
        row
        for row in mitigation
        if row.get("action", "").strip() == DROP_ACTION
    ]
    unique_drop_attackers = sorted(
        {
            row.get("src_ip", "").strip()
            for row in drop_rows
            if row.get("src_ip", "").strip() in ATTACKER_IPS
        }
    )

    rates = [
        rate
        for rate in (safe_float(row.get("packet_rate")) for row in rows)
        if rate is not None
    ]

    primary_pcap = pcap_results.get("primary", {})

    return {
        "scenario": scenario,
        "traffic_records": len(rows),
        "traffic_start": format_ts(start),
        "traffic_end": format_ts(end),
        "traffic_duration_seconds": round(duration, 6),
        "traffic_records_per_second": round(len(rows) / duration, 6) if duration > 0 else "",
        "normal_count": statuses.get("NORMAL", 0),
        "suspect_count": statuses.get("SUSPECT", 0),
        "attack_confirmed_count": statuses.get(ATTACK_STATUS, 0),
        "drop_active_count": statuses.get("DROP_ACTIVE", 0),
        "max_logged_packet_rate_pps": round(max(rates), 6) if rates else "",
        "drop_event_count": len(drop_rows),
        "unique_drop_attackers": len(unique_drop_attackers),
        "primary_pcap": Path(primary_pcap.get("path", "")).name if primary_pcap else "",
        "pcap_size_bytes": primary_pcap.get("size_bytes", ""),
        "pcap_packet_count": primary_pcap.get("packet_count", ""),
        "pcap_duration_seconds": (
            round(primary_pcap["duration_seconds"], 6)
            if primary_pcap.get("duration_seconds") is not None
            else ""
        ),
        "pcap_average_pps": (
            round(primary_pcap["average_pps"], 6)
            if primary_pcap.get("average_pps") is not None
            else ""
        ),
    }


def print_csv_overview(rows: List[dict], mitigation_rows: List[dict]) -> None:
    statuses = Counter(row.get("detection_status", "") for row in rows)
    start, end, duration = duration_from_rows(rows)

    rates = [
        rate
        for rate in (safe_float(row.get("packet_rate")) for row in rows)
        if rate is not None
    ]

    drop_rows = [
        row
        for row in mitigation_rows
        if row.get("action", "").strip() == DROP_ACTION
    ]

    print(f"  Record traffic_analysis.csv       : {len(rows):,}")
    print(f"  Waktu awal log                    : {format_ts(start)}")
    print(f"  Waktu akhir log                   : {format_ts(end)}")
    print(f"  Durasi log                        : {duration:.3f} detik")
    if duration > 0:
        print(f"  Kepadatan record log              : {len(rows) / duration:.2f} record/detik")
    print(f"  Distribusi detection_status       : {dict(statuses)}")
    print(f"  Packet rate maksimum dalam log    : {max(rates):.2f} pps" if rates else
          "  Packet rate maksimum dalam log    : -")
    print(f"  Event {DROP_ACTION}                 : {len(drop_rows)}")


def print_pcap_overview(pcap_results: Dict[str, dict]) -> None:
    subsection("Metadata PCAP")

    print(
        f"  {'Jenis':<22} {'File':<38} {'Paket':>10} "
        f"{'Durasi':>12} {'Avg pps':>12} {'Ukuran':>12}"
    )
    print("  " + "-" * 112)

    for role, info in pcap_results.items():
        filename = Path(info.get("path", "")).name

        if not info.get("exists"):
            print(f"  {role:<22} {filename:<38} {'TIDAK ADA':>10}")
            continue

        packet_text = (
            f"{info['packet_count']:,}"
            if info.get("packet_count") is not None
            else "-"
        )
        duration_text = (
            f"{info['duration_seconds']:.3f}s"
            if info.get("duration_seconds") is not None
            else "-"
        )
        pps_text = (
            f"{info['average_pps']:.2f}"
            if info.get("average_pps") is not None
            else "-"
        )

        print(
            f"  {role:<22} {filename:<38} {packet_text:>10} "
            f"{duration_text:>12} {pps_text:>12} "
            f"{human_size(info.get('size_bytes')):>12}"
        )

        if info.get("error"):
            print(f"      [i] {info['error']}")


# ============================================================================
# ANALISIS PER SKENARIO
# ============================================================================

def analyze_baseline(
    rows: Optional[List[dict]],
    mitigation_rows: Optional[List[dict]],
    checks: List[Tuple[str, bool]],
) -> None:
    section(SCENARIOS["baseline"]["label"])

    if rows is None or mitigation_rows is None:
        print("  [!] Analisis baseline tidak dapat dilanjutkan karena file tidak valid.")
        checks.append(("Baseline: file CSV tersedia dan valid", False))
        return

    print_csv_overview(rows, mitigation_rows)

    statuses = Counter(row.get("detection_status", "") for row in rows)
    drop_rows = [
        row for row in mitigation_rows
        if row.get("action", "").strip() == DROP_ACTION
    ]

    no_attack = statuses.get(ATTACK_STATUS, 0) == 0
    no_drop = len(drop_rows) == 0

    checks.extend(
        [
            ("Baseline: tidak ada ATTACK_CONFIRMED", no_attack),
            ("Baseline: tidak ada DROP_ICMP", no_drop),
        ]
    )

    print()
    print(f"  [{pass_label(no_attack)}] Tidak ada {ATTACK_STATUS}")
    print(f"  [{pass_label(no_drop)}] Tidak ada {DROP_ACTION}")


def build_attacker_timing_rows(
    scenario: str,
    traffic_rows: List[dict],
    mitigation_rows: List[dict],
) -> List[dict]:
    first_observed = first_rows_per_attacker(
        traffic_rows,
        lambda row: (
            row.get("dst_ip", "").strip() == VICTIM_IP
            and row.get("protocol_name", "").strip().upper() == "ICMP"
        ),
    )

    first_confirmed = first_rows_per_attacker(
        traffic_rows,
        lambda row: (
            row.get("dst_ip", "").strip() == VICTIM_IP
            and row.get("detection_status", "").strip() == ATTACK_STATUS
        ),
    )

    first_drop = first_rows_per_attacker(
        mitigation_rows,
        lambda row: row.get("action", "").strip() == DROP_ACTION,
    )

    result = []

    for ip in ATTACKER_IPS:
        observed_row = first_observed.get(ip)
        confirmed_row = first_confirmed.get(ip)
        drop_row = first_drop.get(ip)

        observed_ts = parse_ts(observed_row.get("timestamp")) if observed_row else None
        confirmed_ts = parse_ts(confirmed_row.get("timestamp")) if confirmed_row else None
        drop_ts = parse_ts(drop_row.get("timestamp")) if drop_row else None

        detection_delay = None
        if observed_ts is not None and confirmed_ts is not None:
            detection_delay = (confirmed_ts - observed_ts).total_seconds()

        mitigation_delay = None
        if confirmed_ts is not None and drop_ts is not None:
            mitigation_delay = (drop_ts - confirmed_ts).total_seconds()

        confirmed_rate = (
            safe_float(confirmed_row.get("packet_rate"))
            if confirmed_row
            else None
        )

        result.append(
            {
                "scenario": scenario,
                "attacker_ip": ip,
                "first_observed_timestamp": format_ts(observed_ts),
                "first_attack_confirmed_timestamp": format_ts(confirmed_ts),
                "first_attack_confirmed_rate_pps": (
                    round(confirmed_rate, 6)
                    if confirmed_rate is not None
                    else ""
                ),
                "detection_delay_seconds": (
                    round(detection_delay, 6)
                    if detection_delay is not None
                    else ""
                ),
                "first_drop_timestamp": format_ts(drop_ts),
                "mitigation_delay_seconds": (
                    round(mitigation_delay, 6)
                    if mitigation_delay is not None
                    else ""
                ),
                "mitigation_deviation_from_target_seconds": (
                    round(
                        mitigation_delay - MITIGATION_DELAY_TARGET_SECONDS,
                        6,
                    )
                    if mitigation_delay is not None
                    else ""
                ),
            }
        )

    return result


def print_attacker_detection_table(timing_rows: List[dict]) -> None:
    subsection("Waktu deteksi per attacker")

    print(
        f"  {'Attacker':<13} {'Traffic pertama':<27} "
        f"{'ATTACK_CONFIRMED pertama':<27} {'Delay':>10} {'Rate':>12}"
    )
    print("  " + "-" * 96)

    for row in timing_rows:
        detection_delay = row["detection_delay_seconds"]
        delay_text = (
            f"{float(detection_delay):.3f}s"
            if detection_delay != ""
            else "-"
        )
        rate = row["first_attack_confirmed_rate_pps"]
        rate_text = f"{float(rate):.2f}pps" if rate != "" else "-"

        print(
            f"  {row['attacker_ip']:<13} "
            f"{row['first_observed_timestamp']:<27} "
            f"{row['first_attack_confirmed_timestamp']:<27} "
            f"{delay_text:>10} {rate_text:>12}"
        )


def analyze_ddos_unmitigated(
    rows: Optional[List[dict]],
    mitigation_rows: Optional[List[dict]],
    checks: List[Tuple[str, bool]],
) -> List[dict]:
    section(SCENARIOS["ddos_unmitigated"]["label"])

    if rows is None or mitigation_rows is None:
        print("  [!] Analisis unmitigated tidak dapat dilanjutkan karena file tidak valid.")
        checks.append(("Unmitigated: file CSV tersedia dan valid", False))
        return []

    print_csv_overview(rows, mitigation_rows)

    timing_rows = build_attacker_timing_rows(
        "ddos_unmitigated",
        rows,
        mitigation_rows,
    )
    print_attacker_detection_table(timing_rows)

    confirmed_ips = {
        row["attacker_ip"]
        for row in timing_rows
        if row["first_attack_confirmed_timestamp"] != "-"
    }
    drop_rows = [
        row for row in mitigation_rows
        if row.get("action", "").strip() == DROP_ACTION
    ]

    all_detected = confirmed_ips == set(ATTACKER_IPS)
    no_drop = len(drop_rows) == 0

    rates_above_threshold = []
    for row in timing_rows:
        rate = row["first_attack_confirmed_rate_pps"]
        if rate == "":
            rates_above_threshold.append(False)
        else:
            rates_above_threshold.append(float(rate) >= DETECTION_THRESHOLD_PPS)

    threshold_ok = all(rates_above_threshold)

    checks.extend(
        [
            ("Unmitigated: seluruh attacker ATTACK_CONFIRMED", all_detected),
            ("Unmitigated: tidak ada DROP_ICMP", no_drop),
            (
                f"Unmitigated: rate ATTACK_CONFIRMED >= {DETECTION_THRESHOLD_PPS:.1f} pps",
                threshold_ok,
            ),
        ]
    )

    print()
    print(
        f"  [{pass_label(all_detected)}] "
        f"ATTACK_CONFIRMED terdeteksi untuk {len(confirmed_ips)}/{len(ATTACKER_IPS)} attacker"
    )
    print(f"  [{pass_label(no_drop)}] Mitigasi nonaktif: tidak ada {DROP_ACTION}")
    print(
        f"  [{pass_label(threshold_ok)}] Rate pada ATTACK_CONFIRMED pertama "
        f">= threshold {DETECTION_THRESHOLD_PPS:.1f} pps"
    )
    print(
        "  [i] Rate dekat threshold hanya menunjukkan titik keputusan controller; "
        "bukan bukti tunggal bahwa EWMA tidak digunakan."
    )

    return timing_rows


def analyze_ddos_mitigated(
    rows: Optional[List[dict]],
    mitigation_rows: Optional[List[dict]],
    checks: List[Tuple[str, bool]],
) -> List[dict]:
    section(SCENARIOS["ddos_mitigated"]["label"])

    if rows is None or mitigation_rows is None:
        print("  [!] Analisis mitigated tidak dapat dilanjutkan karena file tidak valid.")
        checks.append(("Mitigated: file CSV tersedia dan valid", False))
        return []

    print_csv_overview(rows, mitigation_rows)

    timing_rows = build_attacker_timing_rows(
        "ddos_mitigated",
        rows,
        mitigation_rows,
    )
    print_attacker_detection_table(timing_rows)

    subsection("Delay ATTACK_CONFIRMED pertama → DROP_ICMP pertama")

    print(
        f"  {'Attacker':<13} {'ATTACK_CONFIRMED':<27} {'DROP_ICMP':<27} "
        f"{'Delay':>10} {'Deviasi 8s':>14}"
    )
    print("  " + "-" * 98)

    mitigation_delays = []
    confirmed_count = 0
    dropped_count = 0

    for row in timing_rows:
        confirmed = row["first_attack_confirmed_timestamp"]
        dropped = row["first_drop_timestamp"]
        delay = row["mitigation_delay_seconds"]
        deviation = row["mitigation_deviation_from_target_seconds"]

        if confirmed != "-":
            confirmed_count += 1
        if dropped != "-":
            dropped_count += 1

        if delay == "":
            delay_text = "-"
            deviation_text = "-"
        else:
            delay_value = float(delay)
            deviation_value = float(deviation)
            mitigation_delays.append(delay_value)
            delay_text = f"{delay_value:.3f}s"
            deviation_text = f"{deviation_value:+.3f}s"

        print(
            f"  {row['attacker_ip']:<13} {confirmed:<27} {dropped:<27} "
            f"{delay_text:>10} {deviation_text:>14}"
        )

    all_detected = confirmed_count == len(ATTACKER_IPS)
    all_dropped = dropped_count == len(ATTACKER_IPS)

    delay_ok = (
        len(mitigation_delays) == len(ATTACKER_IPS)
        and all(
            abs(delay - MITIGATION_DELAY_TARGET_SECONDS)
            <= MITIGATION_DELAY_TOLERANCE_SECONDS
            for delay in mitigation_delays
        )
    )

    checks.extend(
        [
            ("Mitigated: seluruh attacker ATTACK_CONFIRMED", all_detected),
            ("Mitigated: satu DROP_ICMP untuk setiap attacker", all_dropped),
            (
                "Mitigated: delay DROP berada dalam toleransi target",
                delay_ok,
            ),
        ]
    )

    print()

    if mitigation_delays:
        average_delay = sum(mitigation_delays) / len(mitigation_delays)
        max_deviation = max(
            abs(delay - MITIGATION_DELAY_TARGET_SECONDS)
            for delay in mitigation_delays
        )
        print(
            f"  Rata-rata delay mitigasi           : "
            f"{average_delay:.3f} detik"
        )
        print(
            f"  Deviasi maksimum dari target 8 s   : "
            f"{max_deviation:.3f} detik"
        )
    else:
        print("  Rata-rata delay mitigasi           : -")
        print("  Deviasi maksimum dari target 8 s   : -")

    print(
        f"  [{pass_label(all_detected)}] "
        f"{confirmed_count}/{len(ATTACKER_IPS)} attacker ATTACK_CONFIRMED"
    )
    print(
        f"  [{pass_label(all_dropped)}] "
        f"{dropped_count}/{len(ATTACKER_IPS)} attacker memiliki DROP_ICMP"
    )
    print(
        f"  [{pass_label(delay_ok)}] Delay mitigasi berada pada "
        f"{MITIGATION_DELAY_TARGET_SECONDS:.1f} ± "
        f"{MITIGATION_DELAY_TOLERANCE_SECONDS:.1f} detik"
    )

    return timing_rows


# ============================================================================
# PERBANDINGAN ANTAR SKENARIO
# ============================================================================

def compare_controller_logs(summaries: Dict[str, dict]) -> None:
    section("PERBANDINGAN RECORD CONTROLLER ANTAR SKENARIO")

    print(
        f"  {'Skenario':<22} {'Record CSV':>14} {'Durasi log':>14} "
        f"{'Record/detik':>16} {'ATTACK':>10} {'DROP event':>12}"
    )
    print("  " + "-" * 94)

    for scenario in SCENARIOS:
        summary = summaries[scenario]
        duration = float(summary["traffic_duration_seconds"])
        density = summary["traffic_records_per_second"]
        density_text = f"{float(density):.2f}" if density != "" else "-"

        print(
            f"  {scenario:<22} "
            f"{int(summary['traffic_records']):>14,} "
            f"{duration:>13.3f}s "
            f"{density_text:>16} "
            f"{int(summary['attack_confirmed_count']):>10,} "
            f"{int(summary['drop_event_count']):>12,}"
        )

    print()
    print(
        "  [i] Record CSV adalah event/log controller, bukan jumlah paket PCAP. "
        "Karena itu, efektivitas traffic dibandingkan menggunakan metadata PCAP."
    )


def compare_primary_pcaps(
    pcap_data: Dict[str, Dict[str, dict]],
) -> None:
    section("PERBANDINGAN PCAP UTAMA ANTAR SKENARIO")

    print(
        f"  {'Skenario':<22} {'Paket':>14} {'Durasi':>14} "
        f"{'Average pps':>16} {'Ukuran':>14}"
    )
    print("  " + "-" * 86)

    for scenario in SCENARIOS:
        info = pcap_data[scenario].get("primary", {})
        packet_count = info.get("packet_count")
        duration = info.get("duration_seconds")
        average_pps = info.get("average_pps")

        packet_text = f"{packet_count:,}" if packet_count is not None else "-"
        duration_text = f"{duration:.3f}s" if duration is not None else "-"
        pps_text = f"{average_pps:.2f}" if average_pps is not None else "-"

        print(
            f"  {scenario:<22} {packet_text:>14} "
            f"{duration_text:>14} {pps_text:>16} "
            f"{human_size(info.get('size_bytes')):>14}"
        )

    unmit = pcap_data["ddos_unmitigated"].get("primary", {})
    mit = pcap_data["ddos_mitigated"].get("primary", {})

    unmit_packets = unmit.get("packet_count")
    mit_packets = mit.get("packet_count")
    unmit_pps = unmit.get("average_pps")
    mit_pps = mit.get("average_pps")
    unmit_duration = unmit.get("duration_seconds")
    mit_duration = mit.get("duration_seconds")

    if (
        unmit_packets is not None
        and mit_packets is not None
        and unmit_packets > 0
    ):
        packet_reduction = (1.0 - mit_packets / unmit_packets) * 100.0
        print()
        print(
            f"  Reduksi jumlah paket mitigated vs unmitigated : "
            f"{packet_reduction:.2f}%"
        )

    if (
        unmit_pps is not None
        and mit_pps is not None
        and unmit_pps > 0
    ):
        pps_reduction = (1.0 - mit_pps / unmit_pps) * 100.0
        print(
            f"  Reduksi average packet rate                  : "
            f"{pps_reduction:.2f}%"
        )

    if (
        unmit_duration is not None
        and mit_duration is not None
        and max(unmit_duration, mit_duration) > 0
    ):
        duration_difference = abs(unmit_duration - mit_duration)
        relative_difference = (
            duration_difference / max(unmit_duration, mit_duration)
        ) * 100.0

        print(
            f"  Perbedaan durasi capture                     : "
            f"{duration_difference:.3f} detik ({relative_difference:.2f}%)"
        )

        if relative_difference > 10.0:
            print(
                "  [!] Durasi capture berbeda lebih dari 10%. "
                "Gunakan average packet rate sebagai pembanding utama, "
                "bukan hanya jumlah paket absolut."
            )
        else:
            print(
                "  [PASS] Durasi capture relatif sebanding; "
                "jumlah paket absolut dapat digunakan sebagai pembanding tambahan."
            )


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    print("ANALISIS FINAL HASIL TESTING SDN ICMP FLOOD")
    print(f"Project directory : {BASE_DIR}")
    print(f"Archive directory : {ARCHIVE_DIR}")
    print(f"Output directory  : {OUTPUT_DIR}")

    if not ARCHIVE_DIR.exists():
        print(f"\n[!] Archive directory tidak ditemukan: {ARCHIVE_DIR}")
        return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_traffic: Dict[str, Optional[List[dict]]] = {}
    all_mitigation: Dict[str, Optional[List[dict]]] = {}
    all_pcap: Dict[str, Dict[str, dict]] = {}
    summaries: Dict[str, dict] = {}
    checks: List[Tuple[str, bool]] = []

    # Membaca seluruh data terlebih dahulu.
    for scenario, config in SCENARIOS.items():
        scenario_dir = ARCHIVE_DIR / scenario

        traffic_path = scenario_dir / "traffic_analysis.csv"
        mitigation_path = scenario_dir / "mitigation_events.csv"

        all_traffic[scenario] = load_traffic_csv(traffic_path)
        all_mitigation[scenario] = load_mitigation_csv(mitigation_path)

        pcap_results = {}
        for role, filename in config["pcaps"]:
            pcap_results[role] = inspect_pcap(scenario_dir / filename)
        all_pcap[scenario] = pcap_results

        summaries[scenario] = summarize_scenario(
            scenario,
            all_traffic[scenario],
            all_mitigation[scenario],
            pcap_results,
        )

    # Analisis skenario.
    analyze_baseline(
        all_traffic["baseline"],
        all_mitigation["baseline"],
        checks,
    )
    print_pcap_overview(all_pcap["baseline"])

    unmit_timing = analyze_ddos_unmitigated(
        all_traffic["ddos_unmitigated"],
        all_mitigation["ddos_unmitigated"],
        checks,
    )
    print_pcap_overview(all_pcap["ddos_unmitigated"])

    mit_timing = analyze_ddos_mitigated(
        all_traffic["ddos_mitigated"],
        all_mitigation["ddos_mitigated"],
        checks,
    )
    print_pcap_overview(all_pcap["ddos_mitigated"])

    # Perbandingan.
    compare_controller_logs(summaries)
    compare_primary_pcaps(all_pcap)

    # Menulis file ringkasan.
    scenario_summary_path = OUTPUT_DIR / "scenario_analysis_summary.csv"
    attacker_timing_path = OUTPUT_DIR / "attacker_timing_summary.csv"

    scenario_fields = [
        "scenario",
        "traffic_records",
        "traffic_start",
        "traffic_end",
        "traffic_duration_seconds",
        "traffic_records_per_second",
        "normal_count",
        "suspect_count",
        "attack_confirmed_count",
        "drop_active_count",
        "max_logged_packet_rate_pps",
        "drop_event_count",
        "unique_drop_attackers",
        "primary_pcap",
        "pcap_size_bytes",
        "pcap_packet_count",
        "pcap_duration_seconds",
        "pcap_average_pps",
    ]

    timing_fields = [
        "scenario",
        "attacker_ip",
        "first_observed_timestamp",
        "first_attack_confirmed_timestamp",
        "first_attack_confirmed_rate_pps",
        "detection_delay_seconds",
        "first_drop_timestamp",
        "mitigation_delay_seconds",
        "mitigation_deviation_from_target_seconds",
    ]

    write_csv(
        scenario_summary_path,
        scenario_fields,
        [summaries[scenario] for scenario in SCENARIOS],
    )
    write_csv(
        attacker_timing_path,
        timing_fields,
        unmit_timing + mit_timing,
    )

    # Ringkasan validasi.
    section("RINGKASAN VALIDASI")

    failed = 0
    for description, ok in checks:
        print(f"  [{pass_label(ok):<9}] {description}")
        if not ok:
            failed += 1

    print()
    print(f"  File ringkasan skenario : {scenario_summary_path}")
    print(f"  File timing attacker    : {attacker_timing_path}")

    print()
    print("=" * 100)
    if failed == 0:
        print("  HASIL AKHIR: SELURUH VALIDASI PASS")
        print("=" * 100)
        return 0

    print(f"  HASIL AKHIR: {failed} VALIDASI PERLU DICEK ULANG")
    print("=" * 100)
    return 1


if __name__ == "__main__":
    sys.exit(main())