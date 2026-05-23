#!/bin/bash
# =============================================================================
# netns_link.sh — Mininet Namespace Symlink Helper
# =============================================================================
# Jalankan setelah sudo python3 topology/topology.py dan Mininet CLI muncul.
# Script ini membuat symlink /var/run/netns/hX dari PID proses Mininet
# sehingga perintah "ip netns exec hX" bisa langsung dipakai.
#
# Usage:
#   sudo bash topology/netns_link.sh
#
# Jalankan ulang setiap kali Mininet di-restart (mn -c lalu topology.py lagi).
# =============================================================================

set -e

# Host yang perlu di-link
# Victim + host baseline + semua attacker
HOSTS=(h1 h2 h5 h7 h10 h13 h15 h18 h20 h25)

echo ""
echo "========================================"
echo "  Mininet Namespace Symlink Helper"
echo "========================================"
echo ""

# Pastikan direktori ada
mkdir -p /var/run/netns

SUCCESS=0
FAILED=0

for host in "${HOSTS[@]}"; do
    # Cari PID proses bash mininet:hX
    PID=$(ps aux | grep "mininet:${host}$" | grep -v grep | awk '{print $2}')

    if [ -z "$PID" ]; then
        echo "  [!] $host — PID tidak ditemukan. Mininet belum jalan atau host tidak ada."
        FAILED=$((FAILED + 1))
        continue
    fi

    # Buat symlink
    ln -sfn /proc/$PID/ns/net /var/run/netns/$host
    echo "  [+] $host → PID $PID → /var/run/netns/$host"
    SUCCESS=$((SUCCESS + 1))
done

echo ""
echo "========================================"
echo "  Selesai: $SUCCESS linked, $FAILED failed"
echo "========================================"
echo ""

# Verifikasi
echo "  Namespace aktif:"
ip netns list | sed 's/^/    /'
echo ""

if [ $FAILED -gt 0 ]; then
    echo "  [!] Pastikan Mininet sudah jalan dan topology.py sudah dieksekusi."
    echo "      Jalankan script ini lagi setelah Mininet CLI muncul."
    exit 1
fi

echo "  [✓] Start: sudo bash /home/kali/sdn-icmp/topology/start_capture.sh (baseline/ddos)"
echo ""
