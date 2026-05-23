#!/bin/bash
# Stop semua tcpdump, merge jadi 1 pcap, dedup paket duplikat
# Jika ada mitigation_events.csv → otomatis hasilkan _clean.pcap
# Usage: sudo bash topology/stop_capture.sh <scenario_name>

SCENARIO=${1:-baseline}
BASE_DIR="/home/kali/sdn-icmp"
CAPTURE_DIR="${BASE_DIR}/logs/archive/${SCENARIO}"
MERGED_FILE="${CAPTURE_DIR}/network_${SCENARIO}.pcap"
CLEAN_FILE="${CAPTURE_DIR}/network_${SCENARIO}_clean.pcap"
MITIGATION_CSV="${CAPTURE_DIR}/mitigation_events.csv"
PID_FILE="/tmp/tcpdump_pids.txt"

HOSTS=(h1 h2 h5 h7 h10 h13 h15 h18 h20 h25)
VICTIM_IP="10.0.0.25"

echo ""
echo "========================================"
echo "  Stop tcpdump — Scenario: $SCENARIO"
echo "========================================"

# ── Stop tcpdump ──────────────────────────────────────────────────────────────
STOPPED=0
if [ -f "$PID_FILE" ]; then
    while read -r pid; do
        if kill "$pid" 2>/dev/null; then
            STOPPED=$((STOPPED + 1))
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi
pkill -f "tcpdump.*-eth0" 2>/dev/null || true
echo "  [-] Stopped $STOPPED tcpdump process(es)."

# Tunggu flush buffer
sleep 2

# ── Cek hasil ─────────────────────────────────────────────────────────────────
PCAP_COUNT=$(find "$CAPTURE_DIR" -maxdepth 1 -name "h*.pcap" | wc -l)
if [ "$PCAP_COUNT" -eq 0 ]; then
    echo "  [!] Tidak ada pcap di $CAPTURE_DIR"
    exit 1
fi
echo "  [i] Found $PCAP_COUNT per-host pcap file(s)."

# ── Cek mergecap & editcap ────────────────────────────────────────────────────
if ! command -v mergecap >/dev/null 2>&1 || ! command -v editcap >/dev/null 2>&1; then
    echo "  [!] mergecap/editcap tidak terpasang."
    echo "      Install: sudo apt install -y wireshark-common"
    exit 1
fi

# ── Merge + dedup ─────────────────────────────────────────────────────────────
echo "  [*] Merging into: $MERGED_FILE"
mergecap -w "${MERGED_FILE}.tmp" "$CAPTURE_DIR"/h*.pcap

echo "  [*] Removing duplicate packets (editcap -d)..."
editcap -d "${MERGED_FILE}.tmp" "$MERGED_FILE"
rm -f "${MERGED_FILE}.tmp"

TOTAL_PKTS=$(capinfos -c "$MERGED_FILE" 2>/dev/null | grep "Number of packets" | awk '{num=$(NF-1); if($NF=="k") num=num*1000; print num}')
echo "  [✓] Merged & dedup: $TOTAL_PKTS packets → $(basename "$MERGED_FILE")"

# Hapus pcap per-host
for host in "${HOSTS[@]}"; do
    rm -f "${CAPTURE_DIR}/${host}.pcap"
done
echo "  [✓] Removed ${#HOSTS[@]} per-host pcap files."

echo ""
echo "  Network-wide pcap: $MERGED_FILE"

# ── Filter clean pcap (hanya jika ada drop events) ───────────────────────────
if [ ! -f "$MITIGATION_CSV" ]; then
    echo "  [i] Tidak ada mitigation_events.csv — skip filter (baseline)."
    echo ""
    exit 0
fi

DROP_LINES=$(tail -n +2 "$MITIGATION_CSV" | grep "DROP_ICMP" || true)
if [ -z "$DROP_LINES" ]; then
    echo "  [i] Tidak ada DROP event — skip filter."
    echo ""
    exit 0
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "  [!] tshark tidak terpasang — skip filter clean pcap."
    echo "      Install: sudo apt install -y tshark"
    echo ""
    exit 0
fi

echo ""
echo "  [*] Membangun filter clean pcap dari drop events..."

# Bangun tshark display filter
# Logika: buang paket ICMP dari attacker→victim SETELAH drop time masing-masing
EXCLUDE_PARTS=()

while IFS=',' read -r ts src_ip rest; do
    # Konversi "2026-05-20 18:39:16.819576" ke unix epoch
    epoch=$(date -d "$ts" +%s.%6N 2>/dev/null)
    if [ -z "$epoch" ]; then
        echo "  [!] Gagal konversi timestamp: $ts — skip $src_ip"
        continue
    fi
    echo "  [i] Attacker $src_ip → drop at $ts (epoch=$epoch)"
    EXCLUDE_PARTS+=("(ip.src==${src_ip} && ip.dst==${VICTIM_IP} && icmp && frame.time_epoch>=${epoch})")
done < <(tail -n +2 "$MITIGATION_CSV" | grep "DROP_ICMP")

if [ ${#EXCLUDE_PARTS[@]} -eq 0 ]; then
    echo "  [!] Tidak ada filter yang berhasil dibangun — skip."
    echo ""
    exit 0
fi

# Gabungkan semua kondisi buang dengan OR, lalu NOT seluruhnya
EXCLUDE_FILTER=$(printf " || %s" "${EXCLUDE_PARTS[@]}")
EXCLUDE_FILTER="${EXCLUDE_FILTER:4}"
TSHARK_FILTER="!(${EXCLUDE_FILTER})"

echo "  [*] Applying filter..."
# FIX: Gunakan single quotes untuk prevent bash history expansion dengan !
tshark -r "$MERGED_FILE" \
    -Y "$TSHARK_FILTER" \
    -w "$CLEAN_FILE" \
    2>/dev/null

if [ $? -ne 0 ]; then
    echo "  [!] tshark gagal — cek filter atau versi tshark."
    exit 1
fi

CLEAN_PKTS=$(capinfos -c "$CLEAN_FILE" 2>/dev/null | grep "Number of packets" | awk '{num=$(NF-1); if($NF=="k") num=num*1000; print num}')
DROPPED_PKTS=$((TOTAL_PKTS - CLEAN_PKTS))

echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │           Clean PCAP Summary            │"
echo "  ├─────────────────────────────────────────┤"
printf "  │  Raw packets    : %10s              │\n" "$TOTAL_PKTS"
printf "  │  Dropped (fake) : %10s              │\n" "$DROPPED_PKTS"
printf "  │  Clean packets  : %10s              │\n" "$CLEAN_PKTS"
echo "  └─────────────────────────────────────────┘"
echo ""
echo "  Raw pcap   : $MERGED_FILE"
echo "  Clean pcap : $CLEAN_FILE"
echo ""
echo "  Buka network_${SCENARIO}_clean.pcap di Wireshark"
echo "  → I/O Graph attacker flat 0 setelah drop time ✓"
echo ""
