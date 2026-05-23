#!/bin/bash
# Auto-launch tcpdump di 10 host Mininet
# Usage: sudo bash topology/start_capture.sh <scenario_name>

set -e

SCENARIO=${1:-baseline}
BASE_DIR="/home/kali/sdn-icmp"
CAPTURE_DIR="${BASE_DIR}/logs/archive/${SCENARIO}"
PID_FILE="/tmp/tcpdump_pids.txt"

HOSTS=(h1 h2 h5 h7 h10 h13 h15 h18 h20 h25)

echo ""
echo "========================================"
echo "  Start tcpdump — Scenario: $SCENARIO"
echo "========================================"

mkdir -p "$CAPTURE_DIR"
# Hapus pcap per-host lama (kalau ada), JANGAN hapus file merged & CSV
for host in "${HOSTS[@]}"; do
    rm -f "${CAPTURE_DIR}/${host}.pcap"
done
rm -f "$PID_FILE"

# Cek namespace
for host in "${HOSTS[@]}"; do
    if ! ip netns list | grep -q "^${host} "; then
        echo "  [!] Namespace $host tidak ditemukan."
        echo "      Jalankan dulu: sudo bash topology/netns_link.sh"
        exit 1
    fi
done

# Filter: hanya capture protokol & port yang dipakai skenario
FILTER='icmp or arp or (tcp port 5001) or (tcp port 8080) or (udp port 6001)'

# Launch tcpdump per host
for host in "${HOSTS[@]}"; do
    PCAP="${CAPTURE_DIR}/${host}.pcap"
    ip netns exec "$host" \
        tcpdump -i "${host}-eth0" -nn -tt -s 96 \
        "$FILTER" \
        -w "$PCAP" \
        > /dev/null 2>&1 &
    PID=$!
    echo "$PID" >> "$PID_FILE"
    echo "  [+] $host → $PCAP (pid=$PID)"
done

echo ""
echo "  ${#HOSTS[@]} captures running."
echo "  Stop: sudo bash topology/stop_capture.sh $SCENARIO"
echo ""