#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
import subprocess
from collections import defaultdict

PCAP = "network_ddos_mitigated_clean.pcap"
VICTIM_IP = "10.0.0.25"


def run_tshark(display_filter, fields):
    command = ["tshark", "-r", PCAP]

    if display_filter:
        command.extend(["-Y", display_filter])

    command.extend(["-T", "fields"])

    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    rows = []

    for line in result.stdout.splitlines():
        if line.strip():
            rows.append(line.split("\t"))

    return rows


def first_value(value):
    return value.split(",")[0].strip() if value else ""


# ============================================================
# 1. TOTAL PAKET DAN DURASI PCAP
# ============================================================

all_frames = run_tshark(
    "",
    ["frame.time_relative"],
)

total_packets = len(all_frames)
capture_duration = 0.0

if all_frames:
    capture_duration = float(first_value(all_frames[-1][0]))


# ============================================================
# 2. ICMP ECHO REQUEST MENUJU VICTIM
# ============================================================

icmp_request_rows = run_tshark(
    f"icmp.type == 8 && ip.dst == {VICTIM_IP}",
    ["frame.time_relative", "frame.len"],
)

packets_per_second = defaultdict(int)
bytes_per_second = defaultdict(int)

total_echo_request_to_victim = 0
total_bytes_to_victim = 0

for row in icmp_request_rows:
    if len(row) < 2:
        continue

    time_text = first_value(row[0])
    length_text = first_value(row[1])

    if not time_text or not length_text:
        continue

    timestamp = float(time_text)
    frame_length = int(length_text)
    second = math.floor(timestamp)

    packets_per_second[second] += 1
    bytes_per_second[second] += frame_length

    total_echo_request_to_victim += 1
    total_bytes_to_victim += frame_length


# ============================================================
# 3. PACKET RATE DAN THROUGHPUT
# ============================================================

average_packet_rate = (
    total_echo_request_to_victim / capture_duration
    if capture_duration > 0
    else 0.0
)

average_throughput = (
    total_bytes_to_victim / capture_duration
    if capture_duration > 0
    else 0.0
)

if packets_per_second:
    peak_packet_second, peak_packet_rate = max(
        packets_per_second.items(),
        key=lambda item: item[1],
    )
else:
    peak_packet_second = 0
    peak_packet_rate = 0

if bytes_per_second:
    peak_throughput_second, peak_throughput = max(
        bytes_per_second.items(),
        key=lambda item: item[1],
    )
else:
    peak_throughput_second = 0
    peak_throughput = 0


# ============================================================
# 4. OUTPUT UNTUK TABEL
# ============================================================

print("=" * 72)
print("RINGKASAN PEMERIKSAAN PCAP SKENARIO DDOS DENGAN MITIGASI")
print("=" * 72)

print(f"PCAP                                      : {PCAP}")
print(f"Victim                                    : h25 ({VICTIM_IP})")
print(f"Durasi capture                            : {capture_duration:.3f} detik")
print(f"Total paket pada PCAP                     : {total_packets} paket")
print(
    f"Total ICMP echo request menuju victim     : "
    f"{total_echo_request_to_victim} paket"
)
print(
    f"Total ukuran ICMP echo request            : "
    f"{total_bytes_to_victim} byte"
)
print(
    f"Rata-rata packet rate                     : "
    f"{average_packet_rate:.2f} pps"
)
print(
    f"Puncak packet rate                        : "
    f"{peak_packet_rate} pps pada detik ke-{peak_packet_second}"
)
print(
    f"Rata-rata throughput                      : "
    f"{average_throughput:.2f} byte/s"
)
print(
    f"Puncak throughput                         : "
    f"{peak_throughput} byte/s pada detik ke-{peak_throughput_second}"
)

print("=" * 72)
