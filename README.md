# SDN ICMP Flood Forensics & Detection System
## Distributed Attack Detection and Mitigation using NIST SP 800-86 Framework

This project implements a comprehensive SDN-based detection and mitigation system for ICMP flood attacks in a network emulation environment. It follows NIST SP 800-86 digital forensics guidelines across three operational phases: Baseline, Attack, and Recovery.

---

## Project Overview

| Component | Detail |
|-----------|--------|
| **Architecture** | Software-Defined Network (SDN) with OpenFlow 1.3 |
| **Controller** | Ryu (with intelligent attack detection & drop-based mitigation) |
| **Network Emulator** | Mininet |
| **Detection Method** | EWMA-based anomaly detection + SVM classifier |
| **Mitigation Strategy** | Per-attacker IP OpenFlow DROP rules (auto-expiring) |
| **Experiment Duration** | ±3 minutes (60s baseline + 90s attack + 30s recovery) |
| **Victim Target** | h25 (10.0.0.25) |
| **Attack Sources** | h1, h7, h13, h18 (distributed sources) |
| **Forensics Framework** | NIST SP 800-86 (Detection, Containment, Analysis) |


## Network Topology

```
Switch Layer:
┌─────────────────────────────────────────────────┐
│                  Core Switch (s1)                │
└─────────────────────────────────────────────────┘
        ↑            ↑            ↑            ↑
        │            │            │            │
    ┌───┴─┐      ┌───┴─┐      ┌──┴──┐      ┌──┴──┐
    │     │      │     │      │     │      │     │
   s2     s3    s4     s5     s6            
(h1-h6) (h7-h12)(h13-h18)(h19-h24) (h25 - Victim)

Hosts:
- h1, h7, h13, h18: Attack sources (ICMP flood)
- h25: Victim (target of attacks)
- Others: Legitimate traffic generators
```

---

## Project Structure

```
sdn-icmp/
├── controller/
│   └── controller.py          # Ryu OpenFlow controller with detection & mitigation logic
├── topology/
│   ├── topology.py            # Mininet network topology definition
│   ├── start_capture.sh        # Script to start packet capture
│   ├── stop_capture.sh         # Script to stop packet capture
│   └── netns_link.sh           # Network namespace setup
├── training/
│   ├── svm_train.py           # SVM model training for attack classification
│   ├── feature_collector.py   # Extract features from captured packets
│   └── label_dataset.py        # Label training dataset
├── analysis/
│   ├── analyze_baseline.py     # Analyze baseline phase traffic
│   ├── analyze_ddos.py         # Analyze attack phase traffic
│   ├── analyze_combined.py     # Combined 3-phase analysis with visualizations
│   ├── analyze_pcap_baseline.py# PCAP analysis for baseline
│   └── analyze_pcap_ddos.py    # PCAP analysis for DDoS phase
├── data/
│   ├── raw/
│   │   ├── feature_dataset_normal.csv    # Normal traffic features
│   │   └── feature_dataset_attack.csv    # Attack traffic features
│   └── processed/
│       └── feature_dataset_labeled.csv   # Labeled dataset for training
├── logs/
│   ├── archive/
│   │   ├── baseline/           # Baseline phase evidence
│   │   │   ├── session_baseline.pcap
│   │   │   ├── traffic_analysis.csv
│   │   │   └── baseline_summary.md
│   │   └── ddos/               # Attack phase evidence
│   │       ├── session_ddos.pcap
│   │       ├── traffic_analysis.csv
│   │       └── mitigation_events.csv
│   └── report_graphs/          # Generated visualizations
│       ├── baseline/
│       ├── combined/
│       └── ddos/
├── models/
│   ├── svm_model.pkl          # Trained SVM classifier
│   ├── svm_scaler.pkl         # Feature scaling object
│   ├── svm_feature_names.pkl  # Feature names for prediction
│   └── training_report.txt    # Training metrics & summary
├── README.md                   # This file
└── NIST_DOCUMENTATION.md       # Detailed NIST SP 800-86 framework
```

---

## Prerequisites & Installation

### System Requirements
- Linux (Ubuntu 18.04+)
- Python 3.7+
- Root/sudo access (required for Mininet & tcpdump)

### Install Dependencies

```bash
# System packages
sudo apt update
sudo apt install -y \
  mininet \
  openvswitch-switch \
  openvswitch-testcontroller \
  python3-pip \
  tcpdump \
  hping3 \
  iperf \
  tshark \
  wget

# Python packages
pip install -q \
  ryu \
  scapy \
  pandas \
  numpy \
  matplotlib \
  scikit-learn \
  joblib
```

### Clone & Setup

```bash
cd /home/kali
git clone <repo-url> sdn-icmp
cd sdn-icmp
```

---

## Experimental Workflow

### Phase 1: Baseline (60 seconds)
**Objective:** Establish network baseline with legitimate traffic (ICMP, TCP, UDP, HTTP).

| Step | Action |
|------|--------|
| 1 | Start Ryu controller |
| 2 | Launch Mininet topology |
| 3 | Begin tcpdump capture → `logs/archive/baseline/session_baseline.pcap` |
| 4 | Generate mixed traffic (ping, iperf, wget) |
| 5 | Stop capture after 60 seconds |
| 6 | Archive traffic analysis CSV |

### Phase 2: Attack (90 seconds)
**Objective:** Execute distributed ICMP flood while recording detection & mitigation events.

| Step | Action |
|------|--------|
| 1 | Restart controller for attack phase |
| 2 | Start baseline traffic (ping, TCP/UDP) |
| 3 | Begin tcpdump capture → `logs/archive/ddos/session_ddos.pcap` |
| 4 | Launch ICMP flood from h1, h7, h13, h18 (hping3) |
| 5 | Monitor controller logs for detection alerts |
| 6 | Observe DROP rule installation per attacker |
| 7 | Stop attacks after 90 seconds |
| 8 | Archive CSV logs & captured traffic |

### Phase 3: Recovery (30 seconds)
**Objective:** Record network return to normal after attack cessation.

| Step | Action |
|------|--------|
| 1 | Wait 30 seconds (DROP rules expire) |
| 2 | Stop baseline traffic |
| 3 | Stop tcpdump capture |
| 4 | Verify no residual attacks in logs |

---

## Running the Experiment

### Manual Execution (Step-by-Step)

See [README_DOCUMENTATION.md](README_DOCUMENTATION.md) for detailed terminal-by-terminal instructions.

### Quick Start Script (Automated)

```bash
# Clean environment
sudo mn -c && pkill -f ryu-manager && pkill -f tcpdump && \
pkill -f hping3 && pkill -f iperf && rm -f logs/*.csv logs/*.log

# Run experiment
sudo python3 topology/topology.py  # Terminal 1: Mininet
ryu-manager controller/controller.py  # Terminal 2: Controller
# Terminal 3: tcpdump (see documentation)
```

---

## Detection & Mitigation Logic

### Detection Strategy

```
EWMA (Exponential Weighted Moving Average):
├── Packet Rate Threshold: 20 pps
├── Time Window: 5 seconds
├── Sensitivity: Medium (α = 0.3)
└── State: NORMAL → WARNING → ALERT → ATTACK_CONFIRMED

SVM Classifier (ICMP Feature Classification):
├── Features: src_ip, dst_ip, protocol, packet_size, rate
├── Training Data: ICMP packets (normal vs attack)
└── Confidence Threshold: 0.75
```

### Mitigation Strategy

```
OpenFlow DROP Rules (Per-Attacker):
├── Match: src_ip == attacker IP
├── Action: DROP
├── Duration: 60 seconds (auto-expiring)
└── Priority: 100 (high precedence)
```

### Controller Behavior

| State | Condition | Action |
|-------|-----------|--------|
| `NORMAL` | Packet rate < threshold | Log baseline |
| `WARNING` | Rate > threshold for 5s | Log warning event |
| `ALERT` | EWMA trend increasing | Prepare mitigation |
| `ATTACK_CONFIRMED` | SVM confidence > 0.75 | Install DROP rules |
| `MITIGATED` | Attacker IP blocked | Count dropped packets |
| `RELEASED` | 60s timeout expired | Remove DROP rule |

---

## Analysis & Visualization

### Run Post-Experiment Analysis

```bash
# Analyze all phases and generate graphs
python3 analysis/analyze_combined.py

# Output files:
# logs/report_graphs/combined/
#   ├── 01_packet_rate_timeline_3phase.png
#   ├── 02_threat_score_escalation.png
#   ├── 03_detection_state_distribution.png
#   ├── 04_attacker_attribution.png
#   ├── 05_mitigation_lifecycle.png
#   └── comparison_report.md
```

### Expected Visualizations

| File | Shows |
|------|-------|
| `01_packet_rate_timeline_3phase.png` | Packet rate across 3 phases; cliff drop at mitigation |
| `02_threat_score_escalation.png` | Per-attacker threat escalation over time |
| `03_detection_state_distribution.png` | State machine transitions & dwell times |
| `04_attacker_attribution.png` | Attacker identification & PPS contribution |
| `05_mitigation_lifecycle.png` | DROP rule installation/release timeline |

### Individual Phase Analysis

```bash
# Baseline phase only
python3 analysis/analyze_baseline.py

# DDoS phase only
python3 analysis/analyze_ddos.py

# PCAP-level deep dive
python3 analysis/analyze_pcap_baseline.py
python3 analysis/analyze_pcap_ddos.py
```

---

## Training the SVM Classifier

### Prepare Training Data

```bash
# Extract ICMP features from labeled captures
python3 training/feature_collector.py
python3 training/label_dataset.py
```

### Train Model

```bash
python3 training/svm_train.py

# Outputs:
# models/
#   ├── svm_model.pkl        # Trained classifier
#   ├── svm_scaler.pkl       # Feature scaler
#   ├── svm_feature_names.pkl# Feature metadata
#   └── training_report.txt  # Accuracy, precision, recall
```

---

## Expected Results

| Criterion | Expected Outcome |
|-----------|------------------|
| ✅ **Baseline Traffic** | ICMP, TCP, UDP flows recorded; packet rate ~5-15 pps |
| ✅ **Attack Detection** | WARNING logged at 5s; ALERT at 10s; ATTACK_CONFIRMED at 15s |
| ✅ **DROP Rules** | Per-attacker rules installed; 4 attackers identified |
| ✅ **Packet Rate Cliff** | Sharp drop from 100+ pps to <10 pps after mitigation |
| ✅ **Legitimate Traffic** | Baseline pings (h2, h5, h10, h15, h20) continue uninterrupted |
| ✅ **Recovery Phase** | Traffic returns to baseline after 30s; DROP rules expire |
| ✅ **CSV Logs** | traffic_analysis.csv & mitigation_events.csv archived |
| ✅ **PCAP Captures** | session_baseline.pcap & session_ddos.pcap complete |
| ✅ **Visualizations** | All 5 graphs generated successfully |

---

## Forensic Evidence Structure

After a complete 3-phase experiment, evidence is organized as follows:

```
logs/
├── archive/
│   ├── baseline/
│   │   ├── session_baseline.pcap              # Raw packet capture (Phase 1)
│   │   ├── traffic_analysis.csv               # Flow statistics, packet rates
│   │   └── baseline_summary.md                # Baseline metrics report
│   │
│   └── ddos/
│       ├── session_ddos.pcap                  # Raw packet capture (Phases 2-3)
│       ├── traffic_analysis.csv               # Flow stats during attack & recovery
│       ├── mitigation_events.csv              # DROP rule install/release log
│       └── ddos_summary.md                    # Attack analysis report
│
└── report_graphs/
    ├── baseline/
    │   ├── baseline_summary.md                # Baseline narrative
    │   └── baseline_pcap_summary.md           # PCAP analysis
    │
    ├── combined/
    │   ├── comparison_report.md               # 3-phase comparison
    │   ├── 01_packet_rate_timeline_3phase.png # Packet rate across all phases
    │   ├── 02_threat_score_escalation.png    # Per-attacker threat evolution
    │   ├── 03_detection_state_distribution.png # FSM state occupancy
    │   ├── 04_attacker_attribution.png        # Attacker identification chart
    │   └── 05_mitigation_lifecycle.png        # Rule installation timeline
    │
    └── ddos/
        ├── ddos_summary.md                    # Attack phase narrative
        └── ddos_pcap_summary.md               # PCAP attack analysis
```

---

## NIST SP 800-86 Compliance

This project implements the three main phases defined in NIST SP 800-86 (Computer Security Incident Handling Guide):

1. **Detection Phase** (Baseline + Early Attack)
   - Establish normal traffic baseline
   - Monitor for anomalies using EWMA
   - Correlate with SVM classifier

2. **Containment & Mitigation** (Attack Phase)
   - Drop packets from identified attackers
   - Per-attacker granularity using OpenFlow
   - Auto-expiring rules (60-second timeout)

3. **Recovery & Analysis** (Recovery Phase + Post-Experiment)
   - Verify legitimate traffic restoration
   - Archive all evidence (PCAP, CSV logs, events)
   - Generate forensic reports & visualizations

See [NIST_DOCUMENTATION.md](NIST_DOCUMENTATION.md) for detailed framework mapping.

---

## File Descriptions

### Controller

[controller/controller.py](controller/controller.py)
- Main Ryu OpenFlow controller
- Implements EWMA-based anomaly detection
- Queries SVM model for attack confirmation
- Installs/removes DROP rules per attacker

### Topology

[topology/topology.py](topology/topology.py)
- Defines 6-switch Mininet topology
- Creates 25 host nodes across network segments
- Configures OpenFlow 1.3 protocol

### Analysis Scripts

- [analysis/analyze_combined.py](analysis/analyze_combined.py) — Full 3-phase analysis with multi-panel visualizations
- [analysis/analyze_baseline.py](analysis/analyze_baseline.py) — Phase 1 statistics only
- [analysis/analyze_ddos.py](analysis/analyze_ddos.py) — Phase 2-3 analysis
- [analysis/analyze_pcap_baseline.py](analysis/analyze_pcap_baseline.py) — Deep PCAP inspection for baseline
- [analysis/analyze_pcap_ddos.py](analysis/analyze_pcap_ddos.py) — Deep PCAP inspection for attack

### Training

- [training/svm_train.py](training/svm_train.py) — Train SVM classifier on ICMP features
- [training/feature_collector.py](training/feature_collector.py) — Extract ML features from pcap/flows
- [training/label_dataset.py](training/label_dataset.py) — Label attack vs normal samples

---

## Troubleshooting

### Controller Won't Start
```bash
# Check if Ryu is installed
pip show ryu

# Verify OpenFlow switches are available
ovs-vsctl show

# Kill lingering processes
sudo pkill -f ryu-manager
```

### Mininet Topology Fails
```bash
# Clean up residual state
sudo mn -c

# Verify Mininet installation
mn --version

# Test basic topology
sudo python3 -m mininet.clean
```

### Capture Issues
```bash
# Verify tcpdump can access interfaces
sudo tcpdump -i any -l -n | head -20

# Check available network interfaces
ip link show
```

### Analysis Script Errors
```bash
# Verify log files exist
ls -la logs/archive/baseline/
ls -la logs/archive/ddos/

# Check CSV format
head -5 logs/archive/baseline/traffic_analysis.csv
```

---

## Key Features

✅ **Distributed Attack Detection** — Identifies multi-source ICMP flood simultaneously  
✅ **Intelligent Mitigation** — Per-attacker IP granularity; preserves legitimate traffic  
✅ **Anomaly Detection** — EWMA sliding window with SVM confirmation  
✅ **Forensic Completeness** — PCAP, event logs, flow statistics, visualizations  
✅ **NIST-Aligned** — Follows SP 800-86 framework for incident handling  
✅ **Reproducible** — 3-minute cycle suitable for classroom/research labs  

---

## References

- [NIST SP 800-86: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [Ryu Project](https://osrg.github.io/ryu/)
- [Mininet](http://mininet.org/)
- [OpenFlow Specification 1.3](https://www.opennetworking.org/)

---

## License

This project is provided for educational and research purposes. See LICENSE file for details.

---

## Contact & Support

For questions, bug reports, or contributions, please open an issue in the repository.

**Last Updated:** June 2026  
**Status:** Stable
