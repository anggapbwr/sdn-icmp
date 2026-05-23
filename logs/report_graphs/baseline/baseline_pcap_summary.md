# Baseline PCAP — Forensic Analysis Report

**Generated:** 2026-05-21 22:55:07
**Data source:** `logs/archive/baseline/network_baseline.pcap`
**Plane:** Data plane (raw packets, post-merge & dedup)

---

## 1. PCAP Metadata

| Item | Value |
|------|-------|
| File size | 0.25 MB |
| Total packets | 2,419 |
| Total bytes | 286,014 |
| Duration | 136.88 seconds |
| Start time | 2026-05-20 17:24:17 |
| End time | 2026-05-20 17:26:34 |
| Average rate | 17.67 pps |
| Average packet size | 118.2 bytes |
| Unique source IPs | 25 |
| Unique destination IPs | 25 |

---

## 2. Protocol Distribution (Data Plane)

PCAP menunjukkan variasi protokol yang konsisten dengan baseline scenario yang dirancang (ping, TCP transfer, UDP transfer, HTTP, ARP discovery).

| Protocol | Packets | Percentage |
|----------|---------|------------|
| ICMP | 1,382 | 57.1% |
| ARP | 993 | 41.1% |
| TCP | 44 | 1.8% |

![Protocol Breakdown](PB1_protocol_breakdown.png)

---

## 3. Per-Host Traffic Analysis

Top 10 source host paling aktif:

| Source | Packets | Status |
|--------|---------|--------|
| `10.0.0.25` (h25) | 418 | ✅ normal |
| `10.0.0.2` (h2) | 214 | ✅ normal |
| `10.0.0.5` (h5) | 207 | ✅ normal |
| `10.0.0.10` (h10) | 196 | ✅ normal |
| `10.0.0.20` (h20) | 127 | ✅ normal |
| `10.0.0.15` (h15) | 127 | ✅ normal |
| `10.0.0.7` (h7) | 107 | ⚠️ future attacker |
| `10.0.0.13` (h13) | 106 | ⚠️ future attacker |
| `10.0.0.1` (h1) | 103 | ⚠️ future attacker |
| `10.0.0.18` (h18) | 102 | ⚠️ future attacker |

> **Bukti behavior normal**: Host yang nanti jadi attacker (`h1`, `h7`, `h13`, `h18`) di baseline ini menunjukkan paket count **proporsional** dengan host normal — tidak ada dominasi yang mencurigakan.

![Per-Host Traffic](PB2_per_host_traffic.png)

---

## 4. Rate Timeline (Data Plane)

Packet rate stabil di kisaran rendah sepanjang sesi capture. Tidak ada spike yang mengindikasikan flood attempt.

![Rate Timeline](PB3_rate_timeline.png)

---

## 5. Packet Size Analysis

Distribusi ukuran paket konsisten dengan traffic mix normal:
- **ICMP**: biasanya 74-98 bytes (echo request/reply standar)
- **TCP**: bervariasi (handshake kecil + data payload sesuai transfer)
- **UDP**: bervariasi sesuai payload
- **ARP**: 42 bytes (fixed size)

Rata-rata ukuran paket: **118.2 bytes** (Median: **98 bytes**).

![Packet Size Distribution](PB4_packet_size_dist.png)

---

## 6. Forensic Findings

1. **Network baseline terbukti sehat dari sisi data plane** — 2,419 paket dengan rate stabil 17.67 pps
2. **Variasi protokol konsisten** — ICMP, ARP, TCP hadir sesuai skenario traffic mix
3. **Tidak ada flood signature** — tidak ada host yang dominan dengan rate abnormal
4. **Future attackers berperilaku normal** — h1, h7, h13, h18 paket count sebanding dengan normal hosts
5. **Validasi cross-plane** — PCAP (data plane) konsisten dengan CSV controller (control plane)

---

## 7. Validasi Cross-Plane

| Klaim | Bukti CSV (control plane) | Bukti PCAP (data plane) |
|-------|---------------------------|-------------------------|
| Network sehat | 100% NORMAL state | Rate 17.67 pps, no flood |
| Variasi traffic | Multi-protocol di CSV | 3 protokol di PCAP |
| No false positive | 0 WARNING/ATTACK | No abnormal rate spike |

---

*Report ini di-generate otomatis dari `analyze_pcap_baseline.py`. Untuk analisis DDoS PCAP, lihat `ddos_pcap_summary.md`.*
