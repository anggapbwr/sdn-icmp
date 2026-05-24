# SDN-ICMP: Sistem Deteksi & Mitigasi DDoS ICMP Flood Berbasis SDN

> **Skripsi** — Implementasi deteksi dan mitigasi serangan DDoS ICMP Flood menggunakan arsitektur Software-Defined Networking (SDN) dengan framework forensik **NIST SP 800-86**.

---

## Daftar Isi

- [Gambaran Umum](#gambaran-umum)
- [Stack Teknologi](#stack-teknologi)
- [Topologi Jaringan](#topologi-jaringan)
- [Prasyarat & Instalasi](#prasyarat--instalasi)
- [Struktur Direktori](#struktur-direktori)
- [Cara Menjalankan](#cara-menjalankan)
  - [Skenario 1: Baseline](#skenario-1-baseline)
  - [Skenario 2: DDoS](#skenario-2-ddos)
  - [Analisis & Reporting](#analisis--reporting)
- [Kerangka Kerja NIST SP 800-86](#kerangka-kerja-nist-sp-800-86)
- [Output & Evidence](#output--evidence)
- [Referensi](#referensi)

---

## Gambaran Umum

Proyek ini mengimplementasikan sistem deteksi dan mitigasi serangan **DDoS ICMP Flood** di atas jaringan SDN (Software-Defined Networking). Controller Ryu (OpenFlow 1.3) memonitor traffic secara real-time menggunakan algoritma **EWMA + SVM-assisted threshold**, dan secara otomatis memasang aturan DROP di switch OpenFlow ketika serangan terdeteksi.

Seluruh proses eksperimen dipetakan ke **4 fase forensik NIST SP 800-86**: Collection → Examination → Analysis → Reporting.

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  COLLECTION  │ → │ EXAMINATION  │ → │   ANALYSIS   │ → │  REPORTING   │
│  Akuisisi    │   │  Pemrosesan  │   │  Interpretasi│   │  Penyajian   │
│  evidence    │   │  & filtering │   │  forensik    │   │  temuan      │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

---

## Stack Teknologi

| Komponen | Detail |
|---|---|
| OS | Kali Linux |
| Controller | Ryu (OpenFlow 1.3) |
| Emulator Jaringan | Mininet |
| Bahasa | Python 3.8 (venv `ryu38`) |
| Detection Algorithm | EWMA + SVM-assisted threshold |
| Packet Capture | tcpdump, mergecap, editcap, tshark |
| Analisis | pandas, matplotlib, numpy |
| Attack Tool | hping3 |

---

## Topologi Jaringan

```
                        [Controller Ryu]
                              |
                          [s1 - Core]
                    ________|________
                   |    |    |    |  |
                  s2   s3   s4   s5  s6
                  |     |    |    |   |
              h1-h6  h7-h12 h13-h17 h18-h23  h24-h25
```

| Komponen | Detail |
|---|---|
| Core switch | `s1` |
| Access switches | `s2`, `s3`, `s4`, `s5`, `s6` |
| Total hosts | 25 (`h1`–`h25`) |
| **Victim** | `h25` — IP `10.0.0.25`, terhubung ke `s6` |
| **Attacker** | `h1` @ s2, `h7` @ s3, `h13` @ s4, `h18` @ s5 |

### Konfigurasi Detection (controller)

```python
MITIGATION_HARD_TIMEOUT      = 300    # detik
MITIGATION_IDLE_TIMEOUT      = 0
warning_rate_threshold       = 20.0   # pps
attack_rate_threshold        = 50.0   # pps
confirmation_seconds         = 5.0
mitigation_delay_after_alert = 8.0    # delay observasi sebelum DROP
alert_log_interval           = 0.025  # 40 logs/sec
```

---

## Prasyarat & Instalasi

```bash
# OS: Kali Linux atau Ubuntu 24
sudo apt install -y mininet openvswitch-switch wireshark-common tshark hping3

# Python dependencies
pip3 install ryu pandas matplotlib numpy
```

> **Catatan:** Semua perintah eksperimen dijalankan dari direktori `/home/kali/sdn-icmp`.

---

## Struktur Direktori

```
sdn-icmp/
├── controller/
│   └── controller.py           # Ryu controller (EWMA + SVM detection)
├── topology/
│   ├── topology.py             # Definisi topologi Mininet
│   ├── netns_link.sh           # Symlink network namespace per host
│   ├── start_capture.sh        # Launch tcpdump di 10 host
│   └── stop_capture.sh         # Stop tcpdump + merge + filter pcap
├── analysis/
│   ├── analyze_baseline.py     # Analisis CSV skenario baseline
│   ├── analyze_ddos.py         # Analisis CSV skenario DDoS
│   ├── analyze_combined.py     # Perbandingan cross-skenario
│   ├── analyze_pcap_baseline.py# Analisis PCAP skenario baseline
│   └── analyze_pcap_ddos.py    # Analisis PCAP skenario DDoS
└── logs/
    ├── traffic_analysis.csv    # Log real-time controller (live)
    ├── mitigation_events.csv   # Log DROP events (live)
    ├── archive/
    │   ├── baseline/           # Evidence skenario baseline
    │   └── ddos/               # Evidence skenario DDoS
    └── report_graphs/
        ├── baseline/           # Grafik + markdown baseline
        ├── ddos/               # Grafik + markdown DDoS
        └── combined/           # Grafik + markdown perbandingan
```

---

## Cara Menjalankan

Eksperimen membutuhkan **3 terminal** yang berjalan bersamaan:
- **T1** — Ryu Controller
- **T2** — Mininet CLI
- **T3** — Helper scripts (tcpdump, namespace, dll.)

### Skenario 1: Baseline

**Tujuan:** Memvalidasi network dalam kondisi normal — controller tidak menghasilkan false positive.

```bash
# T1 — Start Controller
cd /home/kali/sdn-icmp
ryu-manager controller/controller.py

# T2 — Start Mininet
sudo mn -c
sudo python3 topology/topology.py

# T3 — Link namespace & start capture
sudo bash topology/netns_link.sh
sudo bash topology/start_capture.sh baseline
```

**T2 (Mininet CLI)** — generate traffic mix (~60–90 detik):

```bash
pingall

# ICMP rate rendah ke victim
h2 ping -i 1 10.0.0.25 &
h5 ping -i 1 10.0.0.25 &
h10 ping -i 2 10.0.0.25 &

# TCP transfer
h20 nc -lk -p 5001 > /dev/null &
h15 head -c 100000 /dev/urandom | nc -q 1 10.0.0.20 5001 &

# UDP transfer
h8 nc -ulk -p 6001 > /dev/null &
h16 head -c 50000 /dev/urandom | nc -u -q 1 10.0.0.8 6001 &

# HTTP request
h4 python3 -m http.server 8080 &
h11 curl -s http://10.0.0.4:8080 > /dev/null &
```

**Stop & archive:**

```bash
# T2
exit && sudo mn -c

# T1 — Ctrl+C

# T3
mv /home/kali/sdn-icmp/logs/traffic_analysis.csv  logs/archive/baseline/
mv /home/kali/sdn-icmp/logs/mitigation_events.csv logs/archive/baseline/
sudo bash topology/stop_capture.sh baseline
```

**Output:** `logs/archive/baseline/` berisi `network_baseline.pcap`, `traffic_analysis.csv`, `mitigation_events.csv`.

---

### Skenario 2: DDoS

**Tujuan:** Memvalidasi deteksi & mitigasi serangan distributed ICMP flood dari 4 attacker, sambil membuktikan selektivitas (baseline traffic tidak terganggu).

```bash
# Reset & start ulang (sama seperti baseline)
# T1: ryu-manager controller/controller.py
# T2: sudo mn -c && sudo python3 topology/topology.py
# T3: sudo bash topology/netns_link.sh
# T3: sudo bash topology/start_capture.sh ddos
```

**T2 (Mininet CLI)** — baseline awal (~30 detik), lalu serangan bertahap:

```bash
# Baseline awal
pingall
h2 ping -i 1 10.0.0.25 &
h5 ping -i 1 10.0.0.25 &
h11 ping -i 1 10.0.0.25 &
h16 ping -i 1 10.0.0.25 &
h20 ping -i 1 10.0.0.25 &
h24 ping -i 1 10.0.0.25 &

# Launch attacker bertahap (jeda 15 detik antar attacker)
h1 hping3 --icmp -i u1000 10.0.0.25 &
# tunggu 15 detik
h7 hping3 --icmp -i u1000 10.0.0.25 &
# tunggu 15 detik
h13 hping3 --icmp -i u1000 10.0.0.25 &
# tunggu 15 detik
h18 hping3 --icmp -i u1000 10.0.0.25 &
# tunggu ~60 detik observasi pasca-mitigasi
```

> `hping3 -i u1000` = interval 1000 µs = ~1000 pps per attacker → total ~4000 pps (jauh di atas threshold 50 pps).

**Stop & archive:**

```bash
# T1 — Ctrl+C

# T3
mv /home/kali/sdn-icmp/logs/traffic_analysis.csv  logs/archive/ddos/
mv /home/kali/sdn-icmp/logs/mitigation_events.csv logs/archive/ddos/
sudo bash topology/stop_capture.sh ddos
```

**Output:** `logs/archive/ddos/` berisi `network_ddos.pcap` (raw), `network_ddos_clean.pcap` (post-drop attacker difilter), `traffic_analysis.csv`, `mitigation_events.csv`.

---

### Analisis & Reporting

```bash
cd /home/kali/sdn-icmp

# Control plane (CSV)
python3 analysis/analyze_baseline.py
python3 analysis/analyze_ddos.py
python3 analysis/analyze_combined.py

# Data plane (PCAP)
python3 analysis/analyze_pcap_baseline.py
python3 analysis/analyze_pcap_ddos.py
```

Hasil analisis tersimpan di `logs/report_graphs/{baseline,ddos,combined}/`.

---

## Kerangka Kerja NIST SP 800-86

| Fase | Aktivitas Teknis | Tools | Output |
|---|---|---|---|
| **Collection** | Setup topology Mininet | `topology.py`, `netns_link.sh` | Network siap di-monitor |
| **Collection** | Start network-wide capture | `start_capture.sh`, tcpdump | 10 pcap per-host |
| **Collection** | Start controller logging | `controller.py` (Ryu) | `traffic_analysis.csv`, `mitigation_events.csv` |
| **Examination** | Generate traffic (baseline/DDoS) | Mininet CLI, hping3 | Traffic mix tercatat di CSV & pcap |
| **Examination** | Merge & dedup pcap | mergecap, editcap | `network_${scenario}.pcap` |
| **Examination** | Filter clean pcap | tshark -Y | `network_ddos_clean.pcap` |
| **Analysis** | Parse CSV (control plane) | pandas, matplotlib | Statistik & grafik per skenario |
| **Analysis** | Parse PCAP (data plane) | tshark subprocess | Statistik dari data plane |
| **Analysis** | Cross-plane synthesis | `analyze_combined.py` | Perbandingan baseline vs DDoS |
| **Reporting** | Generate markdown report | Auto-generated analyzer | 5 file `.md` |
| **Reporting** | Konversi ke PDF | VSCode Markdown PDF / pandoc | PDF untuk skripsi |

---

## Output & Evidence

### Grafik yang Dihasilkan

**Baseline (control plane + data plane):**
- `B1` — Distribusi protokol (CSV)
- `B2` — Packet rate timeline (CSV)
- `B3` — Top talkers (CSV)
- `B4` — Validasi 100% NORMAL state (CSV)
- `PB1–PB4` — Distribusi protokol, per-host traffic, rate timeline, packet size (PCAP)

**DDoS (control plane + data plane):**
- `D1` — Attack timeline + DROP markers
- `D2` — Detection latency (Gantt NORMAL→WARNING→ATTACK→DROP)
- `D3` — **Bukti selektivitas** attacker vs baseline (control plane)
- `D4` — Distribusi state machine
- `D5` — Mitigation lifecycle & timing
- `PD3` — **Bukti cliff effect** raw vs clean (data plane)
- `PD4` — Pre/post drop count per attacker (forensik)
- `PD5` — Zoom moment mitigasi

**Combined:**
- `C1–C3` — Perbandingan side-by-side baseline vs DDoS

### Klaim Forensik yang Divalidasi

| # | Klaim | Bukti CSV | Bukti PCAP |
|---|---|---|---|
| 1 | Network baseline sehat | 100% NORMAL state | Rate stabil & rendah |
| 2 | No false positive | 0 WARNING/ATTACK di baseline | No abnormal rate spike |
| 3 | Attacker terdeteksi | WARNING + ATTACK_CONFIRMED events | Top source dominan |
| 4 | Mitigasi terpasang | DROP_ICMP events di CSV | Cliff drop di rate timeline |
| 5 | Drop rule efektif | 0 PacketIn post-drop dari attacker | Rate flat 0 di clean pcap |
| 6 | Selektivitas src-IP | Baseline tetap di phase=MITIGATED | Baseline rate tetap di pcap |
| 7 | Konsistensi timing | Drop latency konsisten antar attacker | Cliff timing sesuai CSV |
| 8 | Cross-plane validation | — | PCAP confirms CSV timestamps |

### Estimasi Waktu Eksekusi

| Aktivitas | Durasi |
|---|---|
| Setup topology + namespace link | ~30 detik |
| Eksperimen baseline | ~2 menit |
| Eksperimen DDoS | ~3 menit |
| Stop capture + merge + filter | ~30 detik |
| Analisis CSV (3 script) | ~10 detik |
| Analisis PCAP (2 script) | 1–5 menit |
| **Total** | **~10 menit** |

---

## Referensi

1. **NIST SP 800-86** — Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to Integrating Forensic Techniques into Incident Response*. NIST.
2. **OpenFlow 1.3 Specification** — Open Networking Foundation.
3. **Ryu Controller** — https://ryu.readthedocs.io/
4. **Mininet** — http://mininet.org/

---

*Project Path: `/home/kali/sdn-icmp` | Framework: NIST SP 800-86 | Generated: Mei 2026*
