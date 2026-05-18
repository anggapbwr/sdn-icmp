# Skenario Eksperimen — SDN ICMP Flood Forensics
## NIST SP 800-86 | 3 Fase: Normal → Attack → Recovery

---

## Informasi Eksperimen

| Item | Detail |
|------|--------|
| Controller | Ryu OpenFlow 1.3 (Drop-Based Mitigation) |
| Emulator | Mininet |
| Detection | EWMA + SVM-assisted threshold |
| Mitigation | OpenFlow DROP rule per attacker IP |
| Total durasi | ±3 menit |
| Victim | h25 — 10.0.0.25 |
| Attacker | h1 (10.0.0.1), h7 (10.0.0.7), h13 (10.0.0.13), h18 (10.0.0.18) |

---

## Topologi

```
s2 (h1–h6)   ──┐
s3 (h7–h12)  ──┤
s4 (h13–h18) ──┼── s1 (core) ── s6 (h19–h25 / victim h25)
s5 (h19–h24) ──┘
```

---

## Terminal yang Dibutuhkan

| Terminal | Fungsi |
|----------|--------|
| Terminal 1 | Ryu Controller |
| Terminal 2 | Mininet CLI |
| Terminal 3 | tcpdump capture |

---

## PERSIAPAN AWAL

### Terminal Ubuntu — Bersihkan Environment

```bash
cd /home/kali/sdn-icmp
```

```bash
sudo mn -c && pkill -f ryu-manager && pkill -f tcpdump && \
pkill -f hping3 && pkill -f iperf && pkill -f "http.server"
```

```bash
rm -f logs/*.csv logs/*.log logs/report_graphs/*
rm -f logs/archive/baseline/* logs/archive/ddos/*
```

---

## FASE 1 — BASELINE (60 detik)

> Tujuan: Rekam traffic normal sebelum serangan. Variatif: ICMP + TCP + UDP + HTTP antar berbagai host.

---

### Step 1 — Terminal 1 · Jalankan Controller

```bash
cd /home/kali/sdn-icmp
ryu-manager controller/controller.py
```

Tunggu hingga semua switch connected (s1–s6 muncul di log controller).

---

### Step 2 — Terminal 2 · Jalankan Mininet

```bash
cd /home/kali/sdn-icmp
sudo python3 topology/topology.py
```

Tunggu Mininet CLI muncul, lalu verifikasi:

```
mininet> pingall
```

---

### Step 3 — Terminal 3 · Mulai Capture Baseline

```bash
sudo tcpdump -i any net 10.0.0.0/24 \
  -w /home/kali/sdn-icmp/logs/archive/baseline/session_baseline.pcap &
```

> **Catatan:** `-i any` merekam semua interface. Duplikasi paket mungkin terjadi tapi valid untuk keperluan forensik.

---

### Step 4 — Mininet CLI · Generate Baseline Traffic

Jalankan semua blok berikut. Copy-paste per blok.

#### HTTP Server di victim

```
h25 python3 -m http.server 80 &
```

#### ICMP baseline dari host normal ke victim

```
h2 ping -i 0.5 10.0.0.25 &
h5 ping -i 0.5 10.0.0.25 &
h10 ping -i 0.5 10.0.0.25 &
h15 ping -i 0.5 10.0.0.25 &
h20 ping -i 0.5 10.0.0.25 &
```

#### ICMP antar host (bukan ke victim)

```
h2 ping -i 1 10.0.0.8 &
h3 ping -i 1 10.0.0.14 &
h9 ping -i 1 10.0.0.19 &
h16 ping -i 1 10.0.0.22 &
h6 ping -i 1 10.0.0.11 &
```

#### TCP — iperf antar segment berbeda

```
h4 iperf -s -p 5001 &
h12 iperf -s -p 5002 &
h17 iperf -s -p 5003 &
h21 iperf -s -p 5004 &
h24 iperf -s -p 5005 &
```

```
h9  iperf -c 10.0.0.4  -p 5001 -t 50 &
h3  iperf -c 10.0.0.12 -p 5002 -t 50 &
h22 iperf -c 10.0.0.17 -p 5003 -t 50 &
h6  iperf -c 10.0.0.21 -p 5004 -t 50 &
h11 iperf -c 10.0.0.24 -p 5005 -t 50 &
```

#### UDP — iperf UDP antar segment berbeda

```
h8  iperf -s -u -p 6001 &
h14 iperf -s -u -p 6002 &
h19 iperf -s -u -p 6003 &
h23 iperf -s -u -p 6004 &
```

```
h2  iperf -c 10.0.0.8  -u -p 6001 -b 1M -t 50 &
h16 iperf -c 10.0.0.14 -u -p 6002 -b 1M -t 50 &
h5  iperf -c 10.0.0.19 -u -p 6003 -b 1M -t 50 &
h20 iperf -c 10.0.0.23 -u -p 6004 -b 1M -t 50 &
```

#### HTTP wget ke victim (TCP variatif)

```
h8  wget -q -O /dev/null http://10.0.0.25/ &
h11 wget -q -O /dev/null http://10.0.0.25/ &
h14 wget -q -O /dev/null http://10.0.0.25/ &
h19 wget -q -O /dev/null http://10.0.0.25/ &
h23 wget -q -O /dev/null http://10.0.0.25/ &
```

**⏱ Tunggu 60 detik.**

---

### Step 5 — Terminal 3 · Hentikan Capture Baseline

```bash
sudo pkill tcpdump
```

---

### Step 6 — Mininet CLI · Hentikan Semua Traffic Baseline

```
h2 pkill ping; h3 pkill ping; h5 pkill ping; h6 pkill ping
h9 pkill ping; h10 pkill ping; h15 pkill ping; h16 pkill ping; h20 pkill ping
h4 pkill iperf; h8 pkill iperf; h9 pkill iperf; h11 pkill iperf
h12 pkill iperf; h14 pkill iperf; h16 pkill iperf; h17 pkill iperf
h19 pkill iperf; h20 pkill iperf; h21 pkill iperf; h22 pkill iperf
h23 pkill iperf; h24 pkill iperf
h8 pkill wget; h11 pkill wget; h14 pkill wget; h19 pkill wget; h23 pkill wget
h25 pkill python3
```

---

### Step 7 — Terminal 1 · Hentikan Controller Baseline

```
CTRL+C
```

---

### Step 8 — Terminal Ubuntu · Arsipkan Evidence Baseline

```bash
mv logs/traffic_analysis.csv logs/archive/baseline/
rm -f logs/*.csv logs/*.log
```

Verifikasi:

```bash
ls -lh logs/archive/baseline/
```

Output yang diharapkan:

```
session_baseline.pcap
traffic_analysis.csv
```

---

## FASE 2 — ATTACK (90 detik)

> Tujuan: Rekam serangan distributed ICMP flood + baseline ping paralel.
> Baseline paralel membuktikan DROP hanya memblokir attacker, host normal tetap lolos.

---

### Step 9 — Terminal 1 · Restart Controller untuk Fase DDoS

```bash
cd /home/kali/sdn-icmp
ryu-manager controller/controller.py
```

Tunggu semua switch connected kembali (s1–s6).

---

### Step 10 — Terminal 3 · Mulai Capture DDoS

```bash
sudo tcpdump -i any net 10.0.0.0/24 \
  -w /home/kali/sdn-icmp/logs/archive/ddos/session_ddos.pcap &
```

---

### Step 11 — Mininet CLI · Jalankan Baseline Paralel

Baseline ping dari host normal ke victim — tetap jalan selama serangan berlangsung.
Ini yang membuktikan mitigasi selektif per-IP di grafik.

```
h2 ping -i 0.5 10.0.0.25 &
h5 ping -i 0.5 10.0.0.25 &
h10 ping -i 0.5 10.0.0.25 &
h15 ping -i 0.5 10.0.0.25 &
h20 ping -i 0.5 10.0.0.25 &
```

TCP/UDP antar host agar traffic tetap variatif saat serangan:

```
h4 iperf -s -p 5001 &
h12 iperf -s -p 5002 &
h3  iperf -c 10.0.0.4  -p 5001 -t 80 &
h9  iperf -c 10.0.0.12 -p 5002 -t 80 &
h8  iperf -s -u -p 6001 &
h16 iperf -c 10.0.0.8  -u -p 6001 -b 1M -t 80 &
```

**⏱ Tunggu 10 detik** agar baseline stabil sebelum serangan dimulai.

---

### Step 12 — Mininet CLI · Mulai Distributed ICMP Flood

```
h1  hping3 --icmp -i u1000 10.0.0.25 &
h7  hping3 --icmp -i u1000 10.0.0.25 &
h13 hping3 --icmp -i u1000 10.0.0.25 &
h18 hping3 --icmp -i u1000 10.0.0.25 &
```

---

### Monitoring — Controller Log (Terminal 1)

| Event | Estimasi waktu | Keterangan |
|-------|---------------|------------|
| ⚠️ WARN | detik ke-5 | Packet rate melewati 20 pps |
| 🚨 ALERT | detik ke-10 | ATTACK_CONFIRMED |
| 🛡️ MITIGATION | detik ke-15 | DROP_RULE_INSTALLED per attacker |
| ✅ INFO | terus-menerus | Baseline ping host normal tetap lolos |

**⏱ Tunggu 90 detik** — biarkan serangan berjalan sampai DROP expire (60 detik dari aktivasi).

---

### Step 13 — Mininet CLI · Hentikan Serangan

```
h1  pkill hping3
h7  pkill hping3
h13 pkill hping3
h18 pkill hping3
```

---

## FASE 3 — RECOVERY (30 detik)

> Tujuan: Rekam traffic kembali normal setelah serangan berhenti.
> DROP rule expire → RELEASE_DROP tercatat → hanya baseline yang tersisa.

**⏱ Tunggu 30 detik** tanpa melakukan apapun.

Yang terjadi di background:
- DROP rule expire (hard_timeout 60s)
- `RELEASE_DROP` tercatat di `mitigation_events.csv`
- Baseline ping dari host normal kembali ke phase `NORMAL` di CSV

---

### Step 14 — Mininet CLI · Hentikan Semua Traffic Recovery

```
h2 pkill ping; h5 pkill ping; h10 pkill ping; h15 pkill ping; h20 pkill ping
h3 pkill iperf; h4 pkill iperf; h8 pkill iperf; h9 pkill iperf
h12 pkill iperf; h16 pkill iperf
```

---

### Step 15 — Terminal 3 · Hentikan Capture DDoS

```bash
sudo pkill tcpdump
```

---

### Step 16 — Terminal 1 · Hentikan Controller DDoS

```
CTRL+C
```

---

### Step 17 — Terminal Ubuntu · Arsipkan Evidence DDoS

```bash
mv logs/traffic_analysis.csv logs/archive/ddos/
mv logs/mitigation_events.csv logs/archive/ddos/
rm -f logs/*.csv logs/*.log
```

Verifikasi:

```bash
ls -lh logs/archive/baseline/
ls -lh logs/archive/ddos/
```

Output yang diharapkan:

```
logs/archive/baseline/
├── session_baseline.pcap
└── traffic_analysis.csv

logs/archive/ddos/
├── session_ddos.pcap
├── traffic_analysis.csv
└── mitigation_events.csv
```

---

## ANALISIS — NIST SP 800-86

### Terminal Ubuntu · Jalankan Telemetry Analyzer

```bash
python3 analysis/analyze.py
```

Output grafik (`analyze.py`):

| File | Isi |
|------|-----|
| `01_packet_rate_timeline_3phase.png` | Timeline 3 fase + cliff mitigasi |
| `02_threat_score_escalation.png` | Eskalasi threat score per attacker |
| `03_detection_state_distribution.png` | Distribusi state machine |
| `04_attacker_attribution.png` | Events + max PPS per attacker |
| `05_mitigation_lifecycle.png` | DROP & RELEASE timeline |

---

### Terminal Ubuntu · Jalankan PCAP Analyzer

```bash
python3 analysis/analyze_pcap.py
```

Output grafik (`analyze_pcap.py`):

| File | Isi |
|------|-----|
| `p01_icmp_volume_protocol.png` | Volume ICMP + distribusi protokol |
| `p02_icmp_rate_per_attacker.png` | Rate timeline per attacker dari PCAP |
| `p03_attacker_icmp_summary.png` | Attribution + PPS per attacker |
| `p04_tcp_degradation.png` | TCP anomali baseline vs DDoS |
| `p05_top_conversation_flows.png` | Top 15 flows attacker → victim |

---

## EXPECTED RESULTS

| Kriteria | Status |
|----------|--------|
| ICMP Flood terdeteksi | ✅ |
| WARNING muncul di controller | ✅ |
| ATTACK_CONFIRMED muncul | ✅ |
| DROP rule terpasang per attacker | ✅ |
| Cliff terlihat di grafik packet rate | ✅ |
| Baseline ping host normal tetap lolos | ✅ |
| Phase MITIGATED tercatat di CSV | ✅ |
| RELEASE_DROP tercatat saat recovery | ✅ |
| Semua 4 attacker teridentifikasi | ✅ |
| Evidence PCAP + CSV berhasil dikumpulkan | ✅ |
| 10 grafik berhasil dibuat | ✅ |

---

## STRUKTUR EVIDENCE AKHIR

```
logs/
├── archive/
│   ├── baseline/
│   │   ├── session_baseline.pcap     ← packet capture fase normal
│   │   └── traffic_analysis.csv      ← telemetry baseline
│   └── ddos/
│       ├── session_ddos.pcap         ← packet capture fase attack + recovery
│       ├── traffic_analysis.csv      ← telemetry 3 fase (phase: NORMAL/ATTACK/MITIGATED)
│       └── mitigation_events.csv     ← DROP_ICMP + RELEASE_DROP events
└── report_graphs/
    ├── 01_packet_rate_timeline_3phase.png
    ├── 02_threat_score_escalation.png
    ├── 03_detection_state_distribution.png
    ├── 04_attacker_attribution.png
    ├── 05_mitigation_lifecycle.png
    ├── p01_icmp_volume_protocol.png
    ├── p02_icmp_rate_per_attacker.png
    ├── p03_attacker_icmp_summary.png
    ├── p04_tcp_degradation.png
    ├── p05_top_conversation_flows.png
    ├── forensic_report.txt
    ├── pcap_forensic_report.txt
    ├── summary_stats.csv
    ├── attacker_summary.csv (jika ada)
    ├── pcap_summary_stats.csv
    ├── pcap_attacker_summary.csv
    └── pcap_conversations_flows.csv
```

---

## CATATAN TEKNIS
a
| Topik | Penjelasan |
|-------|------------|
| tcpdump `-i any` | Merekam semua interface sekaligus. Duplikasi paket bisa terjadi tapi valid untuk forensik. |
| DROP per-IP | `_add_drop_flow` pakai `ipv4_src=attacker_IP` — host normal tidak terkena. |
| Kolom `phase` | Otomatis diisi `NORMAL/ATTACK/MITIGATED` oleh controller di setiap baris CSV. |
| EWMA smoothing | `alpha=0.3` — packet rate dihaluskan untuk mengurangi spike sesaat. |
| DROP timeout | `idle=30s`, `hard=60s` — setelah 60s DROP expire otomatis, state controller direset. |
| Baseline paralel | Ping `-i 0.5` dari 5 host normal ke victim selama serangan — membuktikan selektivitas DROP. |

---

## DEPENDENSI

```bash
# Pastikan semua tersedia sebelum eksperimen
sudo apt install hping3 iperf tshark -y
pip install ryu matplotlib pandas numpy joblib scikit-learn --break-system-packages
```

---

## TRAINING SVM (ICMP FEATURES ONLY)

Model deteksi ICMP flood sekarang dilatih dari:
- `data/raw/feature_dataset_normal.csv`
- `data/raw/feature_dataset_attack.csv`

Fitur yang dipakai (khusus ICMP):
- `is_to_victim`
- `packet_rate_ewma`
- `packet_count_1s`
- `byte_count_1s`
- `avg_pkt_size`
- `pkt_size_std`
- `inter_arrival_std`

Jalankan:

```bash
cd /home/kali/sdn-icmp
python3 training/svm_train.py
```

Output artifacts ke folder `models/`:
- `svm_model.pkl`
- `svm_scaler.pkl`
- `svm_feature_names.pkl`

Controller otomatis load ketiga file tersebut. TCP/UDP/HTTP tetap dicatat di CSV telemetry, tetapi tidak dipakai oleh model SVM ICMP flood.
