#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MonitorSwitch13 - Final Version (Drop-Based Mitigation)
# --------------------------------------------------------
# Skenario 3 fase:
#   Fase 1 - NORMAL  : ping baseline host normal → h25, rate rendah
#   Fase 2 - ATTACK  : flood dari attacker + ping baseline paralel
#                      → WARNING → ATTACK_CONFIRMED → DROP (cliff)
#                      → baseline tetap lolos karena DROP hanya per-IP attacker
#   Fase 3 - POST    : flood berhenti, DROP expire, hanya baseline tersisa
#
# Perubahan dari versi 1 asli:
#   1. Baseline ICMP (non-attacker ke h25) dicatat tiap paket ke CSV → terlihat di grafik
#   2. Throttle console baseline agar tidak spam tapi CSV tetap lengkap
#   3. Setelah DROP expire, detection state direset agar re-arm bersih
#   4. Event note lebih eksplisit: "baseline_icmp_to_victim" vs "icmp_flood_confirmed"
#   5. Mitigation status di CSV eksplisit "DROP_ACTIVE" saat drop berlangsung
#   6. Tambah kolom phase ("NORMAL"/"ATTACK"/"MITIGATED") di traffic_analysis CSV
#      untuk mempermudah visualisasi grafik 3 fase
# --------------------------------------------------------

import os
import csv
import time
import joblib
import numpy as np
import pandas as pd
from collections import deque, defaultdict
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp, arp
from ryu.lib import hub


class MonitorSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    DIM     = "\033[90m"

    SWITCH_DPID_MAP = {
        1: "s1",
        2: "s2",
        3: "s3",
        4: "s4",
        5: "s5",
        6: "s6",
    }

    ATTACKER_IPS = {
        "10.0.0.1":  "h1",
        "10.0.0.7":  "h7",
        "10.0.0.13": "h13",
        "10.0.0.18": "h18",
    }

    VICTIM_IP = "10.0.0.25"

    ATTACKER_SEGMENTS = {
        "10.0.0.1":  (2, "s2-segment-attacker-h1"),
        "10.0.0.7":  (3, "s3-segment-attacker-h7"),
        "10.0.0.13": (4, "s4-segment-attacker-h13"),
        "10.0.0.18": (5, "s5-segment-attacker-h18"),
    }

    def __init__(self, *args, **kwargs):
        super(MonitorSwitch13, self).__init__(*args, **kwargs)

        base_candidates = [
            "/home/kali/sdn-icmp",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        ]
        self.base_dir = next((p for p in base_candidates if os.path.isdir(p)), base_candidates[-1])
        self.logs_dir   = os.path.join(self.base_dir, "logs")
        self.models_dir = os.path.join(self.base_dir, "models")

        self.traffic_analysis_path = os.path.join(self.logs_dir, "traffic_analysis.csv")
        self.mitigation_log_path   = os.path.join(self.logs_dir, "mitigation_events.csv")

        self.model_candidates = [
            os.path.join(self.models_dir, "svm_model.pkl"),
            os.path.join(self.base_dir, "svm_model.pkl"),
        ]
        self.scaler_candidates = [
            os.path.join(self.models_dir, "svm_scaler.pkl"),
            os.path.join(self.base_dir, "svm_scaler.pkl"),
        ]
        self.feature_name_candidates = [
            os.path.join(self.models_dir, "svm_feature_names.pkl"),
            os.path.join(self.base_dir, "svm_feature_names.pkl"),
        ]

        self.mac_to_port = defaultdict(dict)
        self.datapaths   = {}

        # ── Detection thresholds ──────────────────────────────────────────
        self.rate_window_seconds          = 1.0
        self.warning_rate_threshold       = 20.0
        self.attack_rate_threshold        = 50.0
        self.confirmation_seconds         = 5.0
        self.mitigation_delay_after_alert = 5.0

        # ── EWMA ─────────────────────────────────────────────────────────
        self.ewma_alpha = 0.3
        self.ewma_rates = defaultdict(float)

        # ── Console throttle ─────────────────────────────────────────────
        # ALERT & WARN dibuat noisy untuk demo; baseline & info dibatasi
        self.alert_log_interval    = 0.05   # ~20 baris/detik saat flood
        self.warning_log_interval  = 0.1
        self.info_log_interval     = 2.0    # ICMP normal non-victim
        self.baseline_log_interval = 2.0    # baseline ping ke victim

        self.last_alert_log_time   = defaultdict(float)
        self.last_warning_log_time = defaultdict(float)
        self.last_info_log_time    = defaultdict(float)
        self.last_baseline_log_time = defaultdict(float)

        # ── Session state ─────────────────────────────────────────────────
        self.session_packet_times = defaultdict(deque)
        self.session_packet_sizes = defaultdict(deque)
        self.session_stats = defaultdict(lambda: {
            "start_time": None,
            "last_seen":  None,
            "packet_count": 0,
        })

        self.session_detection_state = defaultdict(lambda: {
            "status":          "NORMAL",
            "warning_since":   None,
            "confirmed_since": None,
            "alert_first_seen": None,
            "last_event_time": None,
        })

        self.active_mitigations = defaultdict(lambda: {
            "active":               False,
            "start_time":           None,
            "last_applied_dpid":    None,
            "segment_description":  None,
            "reason":               None,
        })

        self._mitigation_queue  = hub.Queue()
        self._mitigation_thread = hub.spawn(self._mitigation_worker)

        # ── Cleanup ───────────────────────────────────────────────────────
        self._last_cleanup_time  = time.time()
        self._cleanup_interval   = 120.0
        self._session_max_age    = 300.0

        # ── Model ─────────────────────────────────────────────────────────
        self.model         = None
        self.scaler        = None
        self.feature_names = []

        self._startup_banner()
        self._load_model()
        self._init_csv_files()
        self._print_topology_summary()
        self._info("CONTROLLER_READY | Drop-based mitigation | 3-phase scenario ready")

    # ══════════════════════════════════════════════════════════════════════
    # Logging helpers
    # ══════════════════════════════════════════════════════════════════════

    def _paint(self, text, color):
        return f"{color}{text}{self.RESET}"

    def _get_risk_emoji(self, threat_score):
        if threat_score <= 5:  return "🟢"
        if threat_score <= 25: return "🟡"
        if threat_score <= 55: return "🟠"
        return "🔴"

    def _ok(self, msg):
        self.logger.info(self._paint(f"✔️ OK         | {msg}", self.GREEN))

    def _info(self, msg):
        self.logger.info(self._paint(f"✅ INFO       | {msg}", self.GREEN))

    def _warn(self, msg):
        self.logger.warning(self._paint(f"⚠️ WARN       | {msg}", self.YELLOW))

    def _alert(self, msg):
        self.logger.warning(self._paint(f"🚨 ALERT      | {msg}", self.RED))

    def _mitigation(self, msg):
        self.logger.warning(self._paint(f"🛡️ MITIGATION | {msg}", self.MAGENTA))

    def _release(self, msg):
        self.logger.info(self._paint(f"✔️ RELEASE    | {msg}", self.DIM))

    # ── Throttle checkers ─────────────────────────────────────────────────

    def _should_log_alert(self, key):
        now = time.time()
        if (now - self.last_alert_log_time[key]) >= self.alert_log_interval:
            self.last_alert_log_time[key] = now
            return True
        return False

    def _should_log_warning(self, key):
        now = time.time()
        if (now - self.last_warning_log_time[key]) >= self.warning_log_interval:
            self.last_warning_log_time[key] = now
            return True
        return False

    def _should_log_info(self, key):
        now = time.time()
        if (now - self.last_info_log_time[key]) >= self.info_log_interval:
            self.last_info_log_time[key] = now
            return True
        return False

    def _should_log_baseline(self, key):
        now = time.time()
        if (now - self.last_baseline_log_time[key]) >= self.baseline_log_interval:
            self.last_baseline_log_time[key] = now
            return True
        return False

    # ══════════════════════════════════════════════════════════════════════
    # Startup
    # ══════════════════════════════════════════════════════════════════════

    def _startup_banner(self):
        self.logger.info(self._paint("=" * 90, self.CYAN))
        self.logger.info(self._paint("🔒 Ryu SDN ICMP Flood Forensic Controller — Final (Drop-Based)", self.CYAN))
        self.logger.info(self._paint("📊 3-Phase scenario: NORMAL → ATTACK → MITIGATED", self.CYAN))
        self.logger.info(self._paint("🧾 Baseline ping always logged to CSV | Clear cliff on grafik", self.CYAN))
        self.logger.info(self._paint("=" * 90, self.CYAN))

    def _print_topology_summary(self):
        self.logger.info(self._paint("📍 TOPOLOGY | Core=s1 | Access=s2-s6 | Hosts=25 | Victim=10.0.0.25", self.CYAN))
        for ip, hostname in self.ATTACKER_IPS.items():
            _, seg = self.ATTACKER_SEGMENTS[ip]
            self.logger.info(self._paint(f"🔴 ATTACKER   | {ip} ({hostname}) | Segment={seg}", self.RED))

    # ══════════════════════════════════════════════════════════════════════
    # Switch events
    # ══════════════════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self._ok(f"SWITCH_CONNECTED | dpid={datapath.id} | name={self.SWITCH_DPID_MAP.get(datapath.id,'unknown')}")
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self._warn(f"SWITCH_DISCONNECTED | dpid={datapath.id}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Mirror semua ICMP ke controller
        self.add_flow(datapath, 100,
            parser.OFPMatch(eth_type=0x0800, ip_proto=1),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

        # Table-miss
        self.add_flow(datapath, 0,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

        self._ok(f"FLOW_INSTALLED | dpid={datapath.id} | {self.SWITCH_DPID_MAP.get(datapath.id,'unknown')}")

    # ══════════════════════════════════════════════════════════════════════
    # Model
    # ══════════════════════════════════════════════════════════════════════

    def _load_model(self):
        self.model = None
        self.scaler = None
        self.feature_names = []

        for path in self.model_candidates:
            if os.path.exists(path):
                try:
                    self.model = joblib.load(path)
                    self._ok(f"SVM_LOADED | path={path}")
                    break
                except Exception as e:
                    self.logger.error("Failed to load model %s: %s", path, e)

        for path in self.scaler_candidates:
            if os.path.exists(path):
                try:
                    self.scaler = joblib.load(path)
                    self._ok(f"SVM_SCALER_LOADED | path={path}")
                    break
                except Exception as e:
                    self.logger.error("Failed to load scaler %s: %s", path, e)

        for path in self.feature_name_candidates:
            if os.path.exists(path):
                try:
                    names = joblib.load(path)
                    self.feature_names = [str(v) for v in names]
                    self._ok(f"SVM_FEATURE_NAMES_LOADED | path={path}")
                    break
                except Exception as e:
                    self.logger.error("Failed to load feature names %s: %s", path, e)

        if not self.feature_names and self.model is not None:
            self.feature_names = list(getattr(self.model, "feature_names_in_", []))

        if self.model is None:
            self._warn("SVM_NOT_LOADED | Detection=threshold+EWMA only")
        elif self.scaler is None:
            self._warn("SVM_SCALER_NOT_LOADED | Prediction runs without normalization")

    # ══════════════════════════════════════════════════════════════════════
    # CSV
    # ══════════════════════════════════════════════════════════════════════

    def _ensure_csv_with_header(self, path, header):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if (not os.path.exists(path)) or os.path.getsize(path) == 0:
            with open(path, "w", newline="") as f:
                csv.writer(f).writerow(header)

    def _init_csv_files(self):
        # Tambah kolom "phase" untuk memudahkan visualisasi 3 fase di grafik
        traffic_header = [
            "timestamp", "severity", "event_type", "detection_status",
            "mitigation_status", "phase",
            "session_id", "protocol_name",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "src_mac", "dst_mac", "dpid", "dpid_name",
            "in_port", "out_port", "packet_rate", "packet_count",
            "threat_score", "attack_type", "final_prediction",
            "attacker_segment", "event_note",
        ]

        mitigation_header = [
            "timestamp", "src_ip", "attacker_hostname",
            "dpid", "dpid_name", "segment_description",
            "action", "reason", "idle_timeout", "hard_timeout", "note",
        ]

        self._ensure_csv_with_header(self.traffic_analysis_path, traffic_header)
        self._ensure_csv_with_header(self.mitigation_log_path,   mitigation_header)
        self._ok("CSV_READY | traffic_analysis.csv (with phase col) | mitigation_events.csv")

    def _append_csv(self, path, row):
        with open(path, "a", newline="") as f:
            csv.writer(f).writerow(row)

    # ══════════════════════════════════════════════════════════════════════
    # Packet helpers
    # ══════════════════════════════════════════════════════════════════════

    def _get_protocol_name(self, eth_type, ip_proto):
        if eth_type == 0x0806: return "ARP"
        if eth_type == 0x0800:
            if ip_proto == 1:  return "ICMP"
            if ip_proto == 6:  return "TCP"
            if ip_proto == 17: return "UDP"
        return "OTHER"

    def _get_tcp_udp_ports(self, pkt):
        t = pkt.get_protocol(tcp.tcp)
        if t: return t.src_port, t.dst_port
        u = pkt.get_protocol(udp.udp)
        if u: return u.src_port, u.dst_port
        return "", ""

    def _ip_to_number(self, ip_addr):
        if not ip_addr or ip_addr == "0.0.0.0": return 0.0
        try:
            p = ip_addr.split(".")
            return float((int(p[0])<<24)+(int(p[1])<<16)+(int(p[2])<<8)+int(p[3]))
        except Exception:
            return 0.0

    def _mac_to_number(self, mac_addr):
        if not mac_addr: return 0.0
        try:    return float(int(mac_addr.replace(":", ""), 16))
        except: return 0.0

    # ══════════════════════════════════════════════════════════════════════
    # Feature & prediction
    # ══════════════════════════════════════════════════════════════════════

    def _build_feature_dataframe(self, dst_ip, packet_features):
        values = {
            "is_to_victim": float(1 if dst_ip == self.VICTIM_IP else 0),
            "packet_rate_ewma": float(packet_features["packet_rate_ewma"]),
            "packet_count_1s": float(packet_features["packet_count_1s"]),
            "byte_count_1s": float(packet_features["byte_count_1s"]),
            "avg_pkt_size": float(packet_features["avg_pkt_size"]),
            "pkt_size_std": float(packet_features["pkt_size_std"]),
            "inter_arrival_std": float(packet_features["inter_arrival_std"]),
        }
        ordered_columns = self.feature_names or [
            "is_to_victim",
            "packet_rate_ewma",
            "packet_count_1s",
            "byte_count_1s",
            "avg_pkt_size",
            "pkt_size_std",
            "inter_arrival_std",
        ]
        row = {n: values.get(n, 0.0) for n in ordered_columns}
        return pd.DataFrame([row], columns=ordered_columns)

    def _predict_traffic(self, features_df):
        if self.model is None:
            return 0
        try:
            data = features_df.values
            if self.scaler is not None:
                data = self.scaler.transform(data)
            return int(self.model.predict(data)[0])
        except Exception as e:
            self.logger.error("Prediction failed: %s", e)
            return 0

    def _apply_prediction_guard(self, svm_prediction, packet_rate):
        if packet_rate < self.warning_rate_threshold: return 0
        if self.model is None:
            return 1 if packet_rate >= self.attack_rate_threshold else 0
        return int(svm_prediction)

    # ══════════════════════════════════════════════════════════════════════
    # Session & rate
    # ══════════════════════════════════════════════════════════════════════

    def _get_session_id(self, src_ip, dst_ip, protocol_name="", src_port="", dst_port=""):
        if protocol_name in ["TCP","UDP"] and src_port and dst_port:
            return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol_name}"
        return f"{src_ip}->{dst_ip}:{protocol_name}"

    def _get_icmp_window_features(self, session_id, packet_size):
        now = time.time()
        time_q = self.session_packet_times[session_id]
        size_q = self.session_packet_sizes[session_id]
        time_q.append(now)
        size_q.append((now, float(packet_size)))

        while time_q and (now - time_q[0] > self.rate_window_seconds):
            time_q.popleft()
        while size_q and (now - size_q[0][0] > self.rate_window_seconds):
            size_q.popleft()

        raw_rate = float(len(time_q)) / self.rate_window_seconds
        prev = self.ewma_rates[session_id]
        smoothed = self.ewma_alpha * raw_rate + (1.0 - self.ewma_alpha) * prev
        self.ewma_rates[session_id] = smoothed

        sizes = [s for _, s in size_q]
        packet_count_1s = len(sizes)
        byte_count_1s = float(sum(sizes))
        avg_pkt_size = float(byte_count_1s / packet_count_1s) if packet_count_1s > 0 else 0.0
        pkt_size_std = float(np.std(sizes)) if packet_count_1s > 1 else 0.0

        inter_arrival_std = 0.0
        if len(time_q) > 2:
            deltas = np.diff(np.array(time_q, dtype=float))
            if len(deltas) > 1:
                inter_arrival_std = float(np.std(deltas))

        return {
            "packet_rate_ewma": smoothed,
            "packet_count_1s": packet_count_1s,
            "byte_count_1s": byte_count_1s,
            "avg_pkt_size": avg_pkt_size,
            "pkt_size_std": pkt_size_std,
            "inter_arrival_std": inter_arrival_std,
        }

    def _update_session_stats(self, session_id, timestamp_str):
        s = self.session_stats[session_id]
        if s["start_time"] is None: s["start_time"] = timestamp_str
        s["last_seen"]     = timestamp_str
        s["packet_count"] += 1
        return s

    # ══════════════════════════════════════════════════════════════════════
    # Threat scoring & labelling
    # ══════════════════════════════════════════════════════════════════════

    def _calculate_threat_score(self, packet_rate, final_prediction):
        if final_prediction == 0:
            if packet_rate >= 40: return 25
            if packet_rate >= 20: return 12
            return 5
        if packet_rate >= 350: return 95
        if packet_rate >= 250: return 85
        if packet_rate >= 150: return 70
        if packet_rate >= 100: return 55
        return 40

    def _get_attack_type(self, protocol_name, final_prediction, mitigation_active):
        if protocol_name != "ICMP":      return "BENIGN_TRAFFIC"
        if mitigation_active:            return "ICMP_FLOOD_DROPPED"
        if final_prediction == 1:        return "ICMP_FLOOD"
        return "BENIGN_ICMP"

    def _get_attacker_segment(self, src_ip):
        if src_ip in self.ATTACKER_SEGMENTS:
            _, seg = self.ATTACKER_SEGMENTS[src_ip]
            return seg
        return "NORMAL_HOST"

    def _get_phase(self, src_ip, detection_status, mitigation_active):
        """
        Tentukan fase untuk kolom 'phase' di CSV:
          NORMAL     → tidak ada serangan, baseline biasa
          ATTACK     → serangan terdeteksi, belum/sedang mitigasi
          MITIGATED  → DROP aktif, paket attacker diblokir switch
        """
        if mitigation_active:
            return "MITIGATED"
        if detection_status in ("WARNING", "ATTACK_CONFIRMED"):
            return "ATTACK"
        return "NORMAL"

    def _log_state_transition(self, src_ip, old_status, new_status, packet_rate):
        if old_status == new_status:
            return
        if new_status == "WARNING":
            self._warn(
                f"STATE_TRANSITION | {src_ip} | {old_status}→WARN | "
                f"rate={packet_rate:.2f}pps (20-50 pps range)"
            )
        elif new_status == "ATTACK_CONFIRMED":
            self._alert(
                f"STATE_TRANSITION | {src_ip} | {old_status}→ALERT | "
                f"rate={packet_rate:.2f}pps (>{self.attack_rate_threshold} pps or SVM confirmed >{self.confirmation_seconds:.0f}s)"
            )
        elif new_status == "DROP_ACTIVE":
            self._mitigation(
                f"STATE_TRANSITION | {src_ip} | ALERT→DROP | mitigation_status=DROP_ACTIVE"
            )
        elif new_status == "NORMAL" and old_status == "DROP_ACTIVE":
            self._release(
                f"STATE_TRANSITION | {src_ip} | DROP→RELEASE | mitigation window ended"
            )
        elif new_status == "NORMAL":
            self._info(
                f"STATE_TRANSITION | {src_ip} | {old_status}→NORMAL | rate={packet_rate:.2f}pps (<20 pps)"
            )

    # ══════════════════════════════════════════════════════════════════════
    # Detection state machine
    # ══════════════════════════════════════════════════════════════════════

    def _update_detection_state(self, session_id, src_ip, svm_prediction, packet_rate, mitigation_active):
        now = time.time()
        state = self.session_detection_state[session_id]
        old_status = state["status"]
        state["last_event_time"] = now

        if mitigation_active:
            state["status"] = "DROP_ACTIVE"
            self._log_state_transition(src_ip, old_status, state["status"], packet_rate)
            return state

        warning_condition = packet_rate >= self.warning_rate_threshold
        if warning_condition and state["warning_since"] is None:
            state["warning_since"] = now

        elapsed_warning = (now - state["warning_since"]) if state["warning_since"] else 0.0
        alert_condition = (
            packet_rate > self.attack_rate_threshold or
            (svm_prediction == 1 and elapsed_warning >= self.confirmation_seconds)
        )

        if alert_condition:
            state["status"] = "ATTACK_CONFIRMED"
            if state["confirmed_since"] is None:
                state["confirmed_since"] = now
            if state["alert_first_seen"] is None:
                state["alert_first_seen"] = now
        elif warning_condition:
            state["status"] = "WARNING"
        else:
            state["status"] = "NORMAL"
            state["warning_since"] = None
            state["confirmed_since"] = None
            state["alert_first_seen"] = None

        self._log_state_transition(src_ip, old_status, state["status"], packet_rate)
        return state

    def _should_activate_mitigation(self, session_id):
        state = self.session_detection_state[session_id]
        if state["status"] != "ATTACK_CONFIRMED":      return False
        if state["alert_first_seen"] is None:          return False
        return (time.time() - state["alert_first_seen"]) >= self.mitigation_delay_after_alert

    def _get_countdown_seconds(self, session_id):
        state = self.session_detection_state[session_id]
        if state["alert_first_seen"] is None:
            return int(self.mitigation_delay_after_alert)
        elapsed   = time.time() - state["alert_first_seen"]
        remaining = max(0, self.mitigation_delay_after_alert - elapsed)
        return int(remaining)

    # ══════════════════════════════════════════════════════════════════════
    # OpenFlow helpers
    # ══════════════════════════════════════════════════════════════════════

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _send_packet_out(self, datapath, msg, in_port, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        data    = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out     = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _add_drop_flow(self, datapath, src_ip):
        """
        Pasang DROP rule spesifik per attacker IP → victim.
        Host normal TIDAK kena karena match pakai ipv4_src attacker.
        Priority 200 > base flow (10) sehingga override forwarding biasa.
        """
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=1,
            ipv4_src=src_ip,
            ipv4_dst=self.VICTIM_IP,
        )
        self.add_flow(
            datapath=datapath,
            priority=200,
            match=match,
            actions=[],          # empty actions = DROP
            idle_timeout=30,
            hard_timeout=60,
        )

    def _resolve_mitigation_datapath(self, src_ip, fallback_datapath):
        if src_ip in self.ATTACKER_SEGMENTS:
            target_dpid, _ = self.ATTACKER_SEGMENTS[src_ip]
            target_dp = self.datapaths.get(target_dpid)
            if target_dp is not None:
                return target_dp, target_dpid
        return fallback_datapath, fallback_datapath.id

    # ══════════════════════════════════════════════════════════════════════
    # Mitigation worker (async queue)
    # ══════════════════════════════════════════════════════════════════════

    def _mitigation_worker(self):
        while True:
            try:
                task = self._mitigation_queue.get()
                if task is None:
                    break

                action      = task["action"]
                datapath    = task["datapath"]
                src_ip      = task.get("src_ip")
                now_str     = task.get("now_str")
                seg_desc    = task.get("segment_desc", "")
                hostname    = task.get("hostname", "UNKNOWN")
                target_dpid = task.get("target_dpid")

                if action == "ADD":
                    self._add_drop_flow(datapath, src_ip)

                    state = self.active_mitigations[src_ip]
                    state.update({
                        "active":              True,
                        "start_time":          time.time(),
                        "last_applied_dpid":   target_dpid,
                        "segment_description": seg_desc,
                        "reason":              "ATTACK_CONFIRMED_DELAY_PASSED",
                    })

                    self._append_csv(self.mitigation_log_path, [
                        now_str, src_ip, hostname,
                        target_dpid,
                        self.SWITCH_DPID_MAP.get(target_dpid, "unknown"),
                        seg_desc,
                        "DROP_ICMP",
                        "ATTACK_CONFIRMED_DELAY_PASSED",
                        30, 60,
                        f"DROP rule installed — ICMP from {src_ip} blocked at switch level",
                    ])

                    self._mitigation(
                        f"{src_ip} ({hostname}) → {self.VICTIM_IP} | "
                        f"Segment={seg_desc} | DROP_RULE_INSTALLED | "
                        f"Switch={self.SWITCH_DPID_MAP.get(target_dpid,'?')} | ACTIVE"
                    )
                    self._info(
                        f"Baseline ping from normal hosts to {self.VICTIM_IP} "
                        f"continues unaffected — DROP is src-IP specific"
                    )

                elif action == "DELETE":
                    self._append_csv(self.mitigation_log_path, [
                        now_str, src_ip, hostname,
                        target_dpid if target_dpid else "",
                        self.SWITCH_DPID_MAP.get(target_dpid, "unknown") if target_dpid else "",
                        seg_desc,
                        "RELEASE_DROP",
                        "HARD_TIMEOUT_EXPIRED",
                        30, 60,
                        "DROP rule expired — network returned to NORMAL phase",
                    ])
                    self._release(
                        f"{src_ip} | DROP expired | Phase=NORMAL | "
                        f"Baseline traffic only remains"
                    )

            except Exception as e:
                self.logger.error("Mitigation worker error: %s", e)

    # ══════════════════════════════════════════════════════════════════════
    # Mitigation state management
    # ══════════════════════════════════════════════════════════════════════

    def _apply_mitigation_if_needed(self, datapath, src_ip):
        target_dp, target_dpid = self._resolve_mitigation_datapath(src_ip, datapath)
        state = self.active_mitigations[src_ip]

        if state["active"]:
            return "DROP_ACTIVE"

        now_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        _, seg   = self.ATTACKER_SEGMENTS.get(src_ip, (target_dpid, "UNKNOWN_SEGMENT"))
        hostname = self.ATTACKER_IPS.get(src_ip, "UNKNOWN")

        # Set active sebelum queue agar tidak double-trigger
        state["active"]     = True
        state["start_time"] = time.time()

        self._mitigation_queue.put({
            "action":       "ADD",
            "datapath":     target_dp,
            "src_ip":       src_ip,
            "now_str":      now_str,
            "segment_desc": seg,
            "hostname":     hostname,
            "target_dpid":  target_dpid,
        })

        return "DROP_ACTIVE"

    def _refresh_mitigation_state(self, src_ip):
        """
        Cek apakah hard_timeout sudah habis (60 detik).
        Jika iya: reset state + reset log timer agar deteksi bisa arm ulang.
        """
        state = self.active_mitigations[src_ip]

        if not state["active"] or state["start_time"] is None:
            return "OFF"

        elapsed = time.time() - state["start_time"]

        if elapsed >= 60:
            target_dpid = state.get("last_applied_dpid")
            now_str     = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            hostname    = self.ATTACKER_IPS.get(src_ip, "UNKNOWN")
            seg_desc    = state.get("segment_description") or self._get_attacker_segment(src_ip)

            if target_dpid and target_dpid in self.datapaths:
                self._mitigation_queue.put({
                    "action":       "DELETE",
                    "datapath":     self.datapaths[target_dpid],
                    "src_ip":       src_ip,
                    "hostname":     hostname,
                    "target_dpid":  target_dpid,
                    "segment_desc": seg_desc,
                    "now_str":      now_str,
                })

            state.update({
                "active":              False,
                "start_time":          None,
                "last_applied_dpid":   None,
                "segment_description": None,
                "reason":              None,
            })

            # Reset log timer agar fase NORMAL kembali bisa log
            self.last_alert_log_time[src_ip]   = 0.0
            self.last_warning_log_time[src_ip]  = 0.0

            # Reset detection state agar re-arm bersih
            session_id = f"{src_ip}->{self.VICTIM_IP}:ICMP"
            ds = self.session_detection_state[session_id]
            old_status = ds.get("status", "NORMAL")
            ds.update({
                "status":          "NORMAL",
                "warning_since":   None,
                "confirmed_since": None,
                "alert_first_seen": None,
            })
            self._log_state_transition(src_ip, old_status, "NORMAL", 0.0)

            return "OFF"

        return "DROP_ACTIVE"

    # ══════════════════════════════════════════════════════════════════════
    # Session cleanup
    # ══════════════════════════════════════════════════════════════════════

    def _cleanup_stale_sessions(self):
        now   = time.time()
        stale = [sid for sid, q in self.session_packet_times.items()
                 if not q or (now - q[-1]) > self._session_max_age]
        for sid in stale:
            self.session_packet_times.pop(sid, None)
            self.session_packet_sizes.pop(sid, None)
            self.session_stats.pop(sid, None)
            self.session_detection_state.pop(sid, None)
            self.ewma_rates.pop(sid, None)
        if stale:
            self.logger.debug("Session cleanup: %d stale sessions removed", len(stale))

    # ══════════════════════════════════════════════════════════════════════
    # Main packet handler
    # ══════════════════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        now = time.time()
        if (now - self._last_cleanup_time) >= self._cleanup_interval:
            self._cleanup_stale_sessions()
            self._last_cleanup_time = now

        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:
            return

        dpid      = datapath.id
        dpid_name = self.SWITCH_DPID_MAP.get(dpid, "unknown")
        src_mac   = eth.src
        dst_mac   = eth.dst

        self.mac_to_port[dpid][src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        arp_pkt  = pkt.get_protocol(arp.arp)

        # Install forwarding flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions,
                              buffer_id=msg.buffer_id, idle_timeout=30, hard_timeout=60)
            else:
                self.add_flow(datapath, 10, match, actions,
                              idle_timeout=30, hard_timeout=60)

        # ── ARP: forward only, skip log ───────────────────────────────────
        if arp_pkt is not None:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # ── TCP/UDP baseline telemetry ────────────────────────────────────
        if icmp_pkt is None:
            if ip_pkt is not None:
                src_ip   = ip_pkt.src
                dst_ip   = ip_pkt.dst
                proto    = self._get_protocol_name(eth.ethertype, ip_pkt.proto)
                sp, dp   = self._get_tcp_udp_ports(pkt)
                if proto in ["TCP", "UDP"]:
                    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                    session_id = self._get_session_id(src_ip, dst_ip, proto, sp, dp)
                    self._append_csv(self.traffic_analysis_path, [
                        timestamp, "INFO", "NORMAL", "NORMAL", "OFF", "NORMAL",
                        session_id, proto,
                        src_ip, dst_ip,
                        sp if sp else "", dp if dp else "",
                        src_mac, dst_mac, dpid, dpid_name,
                        in_port, out_port if isinstance(out_port, int) else 0,
                        0.0, 1, 5, "BENIGN_TRAFFIC", 0, "NORMAL_HOST",
                        "baseline_normal_traffic",
                    ])
                    key = f"{proto}:{src_ip}->{dst_ip}:{dp}"
                    if self._should_log_baseline(key):
                        self._info(
                            f"NON-ICMP BASELINE | {proto} | "
                            f"{src_ip}:{sp or '-'} → {dst_ip}:{dp or '-'} | "
                            f"Logged to telemetry, excluded from ICMP SVM detection"
                        )
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # ── ICMP only below ───────────────────────────────────────────────
        if ip_pkt is None or icmp_pkt.type != 8:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        packet_size = len(msg.data) if msg.data is not None else 0
        session_id = self._get_session_id(src_ip, dst_ip, "ICMP")
        packet_features = self._get_icmp_window_features(session_id, packet_size)
        packet_rate = packet_features["packet_rate_ewma"]
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        session     = self._update_session_stats(session_id, timestamp)
        packet_count = session["packet_count"]

        # ── ICMP bukan ke victim: log normal, tidak ada deteksi ──────────
        if dst_ip != self.VICTIM_IP:
            self._append_csv(self.traffic_analysis_path, [
                timestamp, "INFO", "NORMAL", "NORMAL", "OFF", "NORMAL",
                session_id, "ICMP",
                src_ip, dst_ip, "", "",
                src_mac, dst_mac, dpid, dpid_name,
                in_port, out_port if isinstance(out_port, int) else 0,
                round(packet_rate, 4), packet_count,
                5, "BENIGN_ICMP", 0, "NORMAL_HOST",
                "normal_icmp_non_victim",
            ])
            key = f"ICMP:{src_ip}->{dst_ip}"
            if self._should_log_info(key):
                self._info(f"ICMP NORMAL | {src_ip} → {dst_ip} | {packet_rate:.2f}pps | Risk=🟢5")
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # ── ICMP ke victim ────────────────────────────────────────────────
        is_attacker = src_ip in self.ATTACKER_IPS

        # Cek mitigation state (hanya untuk attacker)
        mitigation_status = "OFF"
        if is_attacker:
            mitigation_status = self._refresh_mitigation_state(src_ip)
        mitigation_active = (mitigation_status == "DROP_ACTIVE")

        # ── Baseline ping dari host normal ke victim ──────────────────────
        # Selalu log ke CSV (tiap paket) agar terlihat di grafik saat fase MITIGATED
        # Console di-throttle agar tidak spam
        if not is_attacker:
            # Ambil phase dari attacker manapun yang sedang aktif
            any_mitigation = any(
                v["active"] for v in self.active_mitigations.values()
            )
            phase = "MITIGATED" if any_mitigation else "NORMAL"

            self._append_csv(self.traffic_analysis_path, [
                timestamp, "INFO", "NORMAL", "NORMAL", "OFF", phase,
                session_id, "ICMP",
                src_ip, dst_ip, "", "",
                src_mac, dst_mac, dpid, dpid_name,
                in_port, out_port if isinstance(out_port, int) else 0,
                round(packet_rate, 4), packet_count,
                5, "BENIGN_ICMP", 0, "NORMAL_HOST",
                "baseline_icmp_to_victim",
            ])
            key = f"BASELINE:{src_ip}->{dst_ip}"
            if self._should_log_baseline(key):
                self._info(
                    f"BASELINE ICMP | {src_ip} → {dst_ip} | "
                    f"{packet_rate:.2f}pps | Risk=🟢5 | Phase={phase}"
                )
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # ── Attacker traffic ke victim ────────────────────────────────────
        features_df = self._build_feature_dataframe(dst_ip=dst_ip, packet_features=packet_features)
        svm_prediction   = self._predict_traffic(features_df)
        final_prediction = self._apply_prediction_guard(svm_prediction, packet_rate)

        detection_state = self._update_detection_state(
            session_id, src_ip, final_prediction, packet_rate, mitigation_active)
        detection_status = detection_state["status"]

        # Tentukan severity, event_type, event_note, phase
        if mitigation_active:
            final_prediction_log = 0
            severity   = "INFO"
            event_type = "LIMITED"
            event_note = "drop_active_attacker_blocked"
            phase      = "MITIGATED"
        elif detection_status == "ATTACK_CONFIRMED":
            final_prediction_log = final_prediction
            severity   = "ALERT"
            event_type = "ATTACK"
            event_note = "icmp_flood_confirmed"
            phase      = "ATTACK"
        elif detection_status == "WARNING":
            final_prediction_log = final_prediction
            severity   = "WARNING"
            event_type = "SUSPICIOUS"
            event_note = "icmp_rate_warning"
            phase      = "ATTACK"
        else:
            final_prediction_log = final_prediction
            severity   = "INFO"
            event_type = "NORMAL"
            event_note = "normal_icmp_to_victim"
            phase      = "NORMAL"

        # Saat DROP_ACTIVE, rate attacker dipaksa 0 agar grafik menampilkan
        # "cliff down" mitigasi secara eksplisit pada CSV telemetry.
        logged_packet_rate = 0.0 if mitigation_active else packet_rate
        threat_score = self._calculate_threat_score(logged_packet_rate, final_prediction_log)
        risk_emoji       = self._get_risk_emoji(threat_score)
        attack_type      = self._get_attack_type("ICMP", final_prediction_log, mitigation_active)
        attacker_segment = self._get_attacker_segment(src_ip)

        # Saat DROP aktif, attacker seharusnya tidak kirim Packet-In lagi
        # (switch sudah DROP). Tapi kalau masih masuk (burst awal), tetap log
        # ke CSV dengan throttle agar file tidak membengkak.
        should_write_csv = True
        if mitigation_active:
            # Throttle CSV saat drop aktif — cukup 1x/2detik per attacker
            key_csv = f"csv_drop:{src_ip}"
            if not self._should_log_info(key_csv):
                should_write_csv = False

        if should_write_csv:
            self._append_csv(self.traffic_analysis_path, [
                timestamp, severity, event_type, detection_status,
                mitigation_status, phase,
                session_id, "ICMP",
                src_ip, dst_ip, "", "",
                src_mac, dst_mac, dpid, dpid_name,
                in_port, out_port if isinstance(out_port, int) else 0,
                round(logged_packet_rate, 4), packet_count,
                threat_score, attack_type, final_prediction_log,
                attacker_segment, event_note,
            ])

        # ── Console output ────────────────────────────────────────────────
        if mitigation_active:
            # Sangat jarang lolos setelah DROP terpasang — log sekali saja
            if self._should_log_info(f"drop_pass:{src_ip}"):
                self._info(
                    f"DROP ACTIVE | {src_ip} → {dst_ip} | "
                    f"Switch={self.SWITCH_DPID_MAP.get(self.active_mitigations[src_ip].get('last_applied_dpid','?'),'?')} | "
                    f"Phase=MITIGATED"
                )

        elif detection_status == "ATTACK_CONFIRMED":
            if self._should_log_alert(src_ip):
                countdown  = self._get_countdown_seconds(session_id)
                status_txt = f"MITIGATING_IN_{countdown}s" if countdown > 0 else "ACTIVATING_DROP"
                self._alert(
                    f"ICMP FLOOD | {src_ip} → {dst_ip} | "
                    f"{logged_packet_rate:.2f}pps | Risk={risk_emoji}{threat_score} | "
                    f"Pkts={packet_count} | {status_txt}"
                )

            if self._should_activate_mitigation(session_id):
                self._apply_mitigation_if_needed(datapath, src_ip)

        elif detection_status == "WARNING":
            if self._should_log_warning(src_ip):
                ratio = packet_rate / self.warning_rate_threshold
                self._warn(
                    f"ICMP SUSPECT | {src_ip} → {dst_ip} | "
                    f"{logged_packet_rate:.2f}pps | Ratio={ratio:.1f}x | "
                    f"Risk={risk_emoji}{threat_score} | MONITORING"
                )

        else:
            if self._should_log_info(f"ICMP:{src_ip}->{dst_ip}"):
                self._info(
                    f"ICMP NORMAL | {src_ip} → {dst_ip} | "
                    f"{logged_packet_rate:.2f}pps | Risk={risk_emoji}{threat_score}"
                )

        self._send_packet_out(datapath, msg, in_port, actions)
