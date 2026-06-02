# SDN ICMP Flood Mitigation — Comparison Report

**Generated:** 2026-06-01 20:32:01
**Scope:** Side-by-side analysis: Baseline scenario vs DDoS scenario

---

## Executive Summary

Eksperimen ini menggunakan **dua skenario** untuk memvalidasi sistem deteksi & mitigasi DDoS berbasis SDN:

1. **Baseline** — network sehat dengan traffic mix (ICMP, TCP, UDP, HTTP)
2. **DDoS** — 4 attacker melakukan ICMP flood ke victim, controller mendeteksi & mitigasi

### Hasil Utama

| Metric | Baseline | DDoS | Δ Change |
|--------|----------|------|---------:|
| Total events | 3,520 | 7,172 | +103.8% |
| Duration | 222.0s | 186.7s | — |
| Avg packet rate | 1.94 pps | 50.77 pps | **26.2×** |
| Max packet rate | 10.69 pps | 172.13 pps | **16.1×** |
| Unique sources | 25 | 25 | — |
| WARNING events | 0 | 233 | — |
| ATTACK_CONFIRMED | 0 | 3,073 | — |
| Mitigation actions | 0 | 4 | — |

---

## 1. Topologi & Setup

| Item | Detail |
|------|--------|
| Topologi | 1 core switch (s1), 5 access switches (s2-s6), 25 hosts |
| Victim | `10.0.0.25` (h25, attached to s6) |
| Attackers | `10.0.0.1` (h1@s2), `10.0.0.7` (h7@s3), `10.0.0.13` (h13@s4), `10.0.0.18` (h18@s5) |
| Detection | EWMA + SVM-assisted threshold |
| Mitigation | OpenFlow DROP rule (ICMP + ARP) per attacker src-IP |
| Detection thresholds | Warning ≥ 20 pps, Attack > 50 pps |
| Mitigation delay | 8 detik (observasi) setelah ATTACK_CONFIRMED |
| Drop hard timeout | 300 detik |

---

## 2. Protocol Distribution

Baseline scenario menunjukkan **variasi protokol yang sehat** (ICMP, TCP, UDP, ARP) sesuai aktivitas enterprise normal. DDoS scenario didominasi oleh **ICMP** karena 4 attacker melakukan ICMP flood.

![Protocol Comparison](C1_protocol_comparison.png)

| Protocol | Baseline | DDoS | Catatan |
|----------|---------:|-----:|---------|
| ICMP | 3,385 | 7,172 | ↑ Spike karena flood |
| TCP | 24 | 0 |  |
| UDP | 111 | 0 |  |


---

## 3. Packet Rate Comparison

DDoS menghasilkan traffic **16.1× lebih besar** (max rate) dan **26.2× lebih besar** (avg rate) dibanding baseline. Ini secara signifikan melampaui threshold deteksi.

![Packet Rate Comparison](C2_packet_rate_comparison.png)

---

## 4. Detection State Comparison

**Baseline** menunjukkan 100% events terklasifikasi NORMAL (no false positive).
**DDoS** menunjukkan eskalasi state yang sesuai: NORMAL → WARNING → ATTACK_CONFIRMED, dengan DROP_ACTIVE setelah mitigasi.

![Detection State Comparison](C3_state_comparison.png)

---

## 5. Mitigation Evidence (DDoS only)

4 drop rule berhasil terpasang di edge switch sesuai posisi attacker:

| Time | Source IP | Switch | Action |
|------|-----------|--------|--------|
| 22:50:38 | `10.0.0.1` | s2 | DROP_ICMP |
| 22:50:46 | `10.0.0.7` | s3 | DROP_ICMP |
| 22:50:55 | `10.0.0.13` | s4 | DROP_ICMP |
| 22:51:06 | `10.0.0.18` | s5 | DROP_ICMP |

**Karakteristik mitigasi:**
- Drop terpasang di **edge switch** (di switch attacker, bukan di switch victim) → traffic attacker tidak melewati core network
- **Selektif per source IP** → traffic dari host normal ke victim tidak terkena drop
- **Persisten** → hard_timeout 300 detik mencegah re-flood

---

## 6. Detail Per Skenario

### Baseline Scenario

📄 Detail lengkap baseline analysis: `baseline_summary.md`

Embed grafik baseline:
- [B1] Protocol Distribution: `../baseline/B1_protocol_distribution.png`
- [B2] Packet Rate Timeline: `../baseline/B2_packet_rate_timeline.png`
- [B3] Top Talkers: `../baseline/B3_top_talkers.png`
- [B4] Detection States: `../baseline/B4_detection_states.png`

### DDoS Scenario

📄 Detail lengkap DDoS analysis: `ddos_summary.md`

Embed grafik DDoS:
- [D1] Attack Timeline: `../ddos/D1_attack_timeline.png`
- [D2] Detection Latency: `../ddos/D2_detection_latency.png`
- [D3] Attacker vs Baseline: `../ddos/D3_attacker_vs_baseline.png` **(BUKTI UTAMA)**
- [D4] Detection States: `../ddos/D4_detection_states.png`
- [D5] Mitigation Lifecycle: `../ddos/D5_mitigation_lifecycle.png`

---

## 7. Validasi Klaim Skripsi

| Klaim | Bukti (data) | Status |
|-------|--------------|--------|
| Sistem deteksi tidak false-positive | Baseline 100% NORMAL (3,520 events) | ✅ |
| Sistem mendeteksi ICMP flood | 233 WARNING + 3,073 ATTACK_CONFIRMED di DDoS | ✅ |
| Mitigasi terpasang otomatis | 4 drop rule tercatat di `mitigation_events.csv` | ✅ |
| Drop rule efektif (no bypass) | 0 PacketIn attacker→victim di CSV setelah drop timestamp | ✅ |
| Selektivitas src-IP | Baseline traffic tetap mengalir saat `phase=MITIGATED` | ✅ |
| Konsistensi timing | Mitigation latency konsisten antar attacker (delay 8 detik) | ✅ |

---

## 8. Conclusion

Sistem SDN ICMP Flood Detection & Mitigation berhasil divalidasi dengan kedua skenario:

1. **Baseline:** controller tidak menghasilkan alarm palsu pada traffic normal
2. **DDoS:** controller mendeteksi serangan dengan delay terkontrol dan memasang drop rule di edge switch
3. **Selektivitas:** drop rule bersifat src-IP specific, tidak mengganggu legitimate traffic
4. **Persistensi:** drop bertahan selama hard_timeout, tidak ada celah untuk re-flood

Eksperimen ini membuktikan bahwa pendekatan **edge-based mitigation di SDN** efektif menghentikan DDoS ICMP flood tanpa mengorbankan traffic normal.

---

*Generated automatically by `analyze_combined.py`. For granular analysis, lihat `baseline_summary.md` dan `ddos_summary.md`.*
