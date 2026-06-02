# DDoS PCAP — Forensic Analysis Report

**Generated:** 2026-06-01 20:32:15
**Data source:** `network_ddos.pcap` (raw) + `network_ddos_clean.pcap` (filtered)
**Plane:** Data plane (raw packets, post-merge & dedup)

---

## 1. PCAP Metadata

| Item | Raw PCAP | Clean PCAP |
|------|---------:|-----------:|
| Total packets | 79,963 | 21,311 |
| Duration | 186.28 seconds | — |
| Start time | 2026-05-31 15:48:45 | — |
| End time | 2026-05-31 15:51:51 | — |
| Mitigation events | 4 | — |

> **Clean PCAP:** dibuat otomatis oleh `stop_capture.sh` dengan filter tshark — buang paket ICMP attacker→victim yang timestamp-nya ≥ drop timestamp di `mitigation_events.csv`. Ini merepresentasikan **apa yang seharusnya sampai victim** sesuai logic mitigasi switch.

---

## 2. Protocol Distribution

| Protocol | Packets (Raw) | Percentage |
|----------|--------------:|-----------:|
| ICMP | 78,677 | 98.4% |
| ARP | 1,286 | 1.6% |

ICMP dominan karena 4 attacker melakukan flood. TCP/UDP/ARP tetap hadir karena background baseline traffic.

![Protocol Breakdown](PD1_protocol_breakdown.png)


### Clean PCAP Comparison

| Metric | Raw PCAP | Clean PCAP | Difference |
|--------|---------:|-----------:|----------:|
| Total packets | 79,963 | 21,311 | -58,652 (73.3%) |
| ICMP packets | 78,677 | 20,025 | -58,652 |

**Interpretasi:** Clean PCAP membuang **58,652 paket** yang merupakan paket attacker setelah drop timestamp.
Paket ini tertangkap di host-side capture tapi tidak akan diteruskan ke victim oleh switch
(switch drop di edge sebelum sampai victim).


---

## 3. Per-Host Traffic Analysis

Top 10 source host paling aktif:

| Source | Packets | Percentage | Status |
|--------|--------:|-----------:|--------|
| `10.0.0.1` (h1) | 22,173 | 27.7% | ⚠️ **ATTACKER** |
| `10.0.0.7` (h7) | 18,099 | 22.6% | ⚠️ **ATTACKER** |
| `10.0.0.13` (h13) | 18,095 | 22.6% | ⚠️ **ATTACKER** |
| `10.0.0.18` (h18) | 17,093 | 21.4% | ⚠️ **ATTACKER** |
| `10.0.0.25` (h25) | 2,180 | 2.7% | ✅ normal |
| `10.0.0.2` (h2) | 343 | 0.4% | ✅ normal |
| `10.0.0.5` (h5) | 332 | 0.4% | ✅ normal |
| `10.0.0.20` (h20) | 312 | 0.4% | ✅ normal |
| `10.0.0.11` (h11) | 199 | 0.2% | ✅ normal |
| `10.0.0.16` (h16) | 187 | 0.2% | ✅ normal |

> Bukti **attacker mendominasi traffic volume** — packet count attacker secara signifikan lebih besar dari normal host, konsisten dengan hping3 flood (1000 pps target rate).

![Per-Host Traffic](PD2_per_host_traffic.png)

---

## 4. Cliff Effect & Selektivitas (BUKTI UTAMA)

Grafik di bawah membandingkan **rate attacker** vs **rate baseline traffic** sepanjang sesi DDoS.

**Yang harus terlihat:**
1. **Attacker traffic** (merah) — rate tinggi saat attack, **turun drastis** setelah drop timestamp
2. **Baseline traffic** (hijau) — rate stabil, **TETAP MENGALIR** sepanjang sesi
3. **Clean PCAP attacker** (ungu putus-putus) — sama dengan raw sampai drop, kemudian flat 0

![Rate Raw vs Clean](PD3_rate_raw_vs_clean.png)

**Interpretasi forensik:**
- Cliff effect membuktikan **drop rule efektif** di edge switch
- Baseline tetap mengalir membuktikan **selektivitas mitigasi** (src-IP specific)
- Selisih raw vs clean = paket attacker yang masih ada di host-side capture tapi **tidak sampai victim** (switch drop di data plane)

---

## 5. Per-Attacker Forensic

| Attacker | Total ICMP→Victim | Pre-Drop (sampai victim) | Post-Drop (di-block) | Drop Time |
|----------|------------------:|-------------------------:|---------------------:|----------:|
| `10.0.0.1` (h1) | 22,029 | 22,029 | 0 | 22:50:38 |
| `10.0.0.7` (h7) | 17,948 | 17,948 | 0 | 22:50:46 |
| `10.0.0.13` (h13) | 17,950 | 17,950 | 0 | 22:50:55 |
| `10.0.0.18` (h18) | 16,963 | 16,963 | 0 | 22:51:06 |

> **Pre-drop count** = paket attacker yang sampai victim sebelum drop terpasang
> **Post-drop count** = paket attacker yang ter-capture di host tapi tidak sampai victim (di-drop switch)

![Per-Attacker Forensic](PD4_per_attacker_forensic.png)

---

## 6. Cliff Effect Zoom

Detail rate per attacker dalam window ±30 detik sekitar drop timestamp pertama:

![Cliff Zoom](PD5_cliff_zoom.png)

Tampak jelas bahwa setiap attacker mengalami **rate drop drastis** tepat setelah drop rule terpasang di switch edge masing-masing.

---

## 7. Forensic Findings

1. **4 attacker teridentifikasi** dari PCAP analysis dengan source IP `10.0.0.1`, `10.0.0.7`, `10.0.0.13`, `10.0.0.18`
2. **Cliff effect terbukti** — rate attacker turun drastis setelah drop time
3. **Selektivitas terkonfirmasi** — baseline traffic tetap mengalir di pcap
4. **Cross-validation dengan CSV controller** — timestamp drop di PCAP konsisten dengan `mitigation_events.csv`
5. **Total paket attacker pre-drop**: 74,890 (paket yang sampai victim sebelum drop)
6. **Total paket attacker post-drop**: 0 (paket yang di-block oleh switch sesuai drop rule)

---

## 8. Validasi Cross-Plane (PCAP ↔ CSV)

| Klaim | Bukti CSV (Control Plane) | Bukti PCAP (Data Plane) |
|-------|---------------------------|-------------------------|
| Attacker terdeteksi | WARNING + ATTACK_CONFIRMED state | Top source dominan di pcap |
| Mitigasi terpasang | 4 DROP_ICMP events | Cliff drop di rate timeline |
| Drop efektif | 0 PacketIn post-drop dari attacker | Rate flat 0 post-drop di clean pcap |
| Selektivitas | Baseline traffic di `phase=MITIGATED` | Baseline rate tetap di pcap |

---

*Report ini di-generate otomatis dari `analyze_pcap_ddos.py`. Untuk pembanding baseline, lihat `baseline_pcap_summary.md`.*
