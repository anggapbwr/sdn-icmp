#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import time
import joblib
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

        self.base_dir   = "/home/kali/sdn-icmp"
        self.logs_dir   = os.path.join(self.base_dir, "logs")
        self.models_dir = os.path.join(self.base_dir, "models")

        self.traffic_analysis_path = os.path.join(self.logs_dir, "traffic_analysis.csv")
        self.mitigation_log_path   = os.path.join(self.logs_dir, "mitigation_events.csv")

        self.model_candidates = [
            os.path.join(self.models_dir, "svm_model.pkl"),
            os.path.join(self.base_dir, "svm_model.pkl"),
        ]

        self.mac_to_port = defaultdict(dict)
        self.datapaths   = {}

        # Detection
        self.rate_window_seconds = 1.0
        self.warning_rate_threshold = 20.0
        self.attack_rate_threshold = 50.0
        self.confirmation_seconds = 5.0
        self.mitigation_delay_after_alert = 5.0

        # EWMA
        self.ewma_alpha = 0.3
        self.ewma_rates = defaultdict(float)

        # Adaptive OpenFlow meter
        self.light_limit_pps  = 50
        self.medium_limit_pps = 20
        self.heavy_limit_pps  = 5

        self.rate_limit_idle_timeout = 30
        self.rate_limit_hard_timeout = 60
        self.meter_id_base = 100

        # Console throttle
        # WARN & ALERT dibuat sangat hidup/noisy untuk demo DDoS.
        # RL_ACTIVE tetap tidak dominan.
        # Jangan pakai log per-packet langsung.
        self.alert_log_interval = 0.01
        self.warning_log_interval = 0.01
        self.info_log_interval = 1.0
        self.baseline_log_interval = 1.0
        self.limited_log_interval = 1.0
        self.limited_csv_interval = 1.0

        self.session_packet_times = defaultdict(deque)
        self.session_stats = defaultdict(lambda: {
            "start_time": None,
            "last_seen": None,
            "packet_count": 0,
        })

        self.session_detection_state = defaultdict(lambda: {
            "status": "NORMAL",
            "warning_since": None,
            "confirmed_since": None,
            "alert_first_seen": None,
            "last_event_time": None,
        })

        self.active_mitigations = defaultdict(lambda: {
            "active": False,
            "start_time": None,
            "last_applied_dpid": None,
            "segment_description": None,
            "reason": None,
            "meter_id": None,
            "limit_pps": None,
        })

        self._mitigation_queue = hub.Queue()
        self._mitigation_thread = hub.spawn(self._mitigation_worker)

        self.last_alert_log_time = defaultdict(float)
        self.last_warning_log_time = defaultdict(float)
        self.last_info_log_time = defaultdict(float)
        self.last_baseline_log_time = defaultdict(float)
        self.last_limited_log_time = defaultdict(float)
        self.last_limited_csv_time = defaultdict(float)

        self._last_cleanup_time = time.time()
        self._cleanup_interval = 120.0
        self._session_max_age = 300.0

        self.model = None
        self.feature_names = []

        self._startup_banner()
        self._load_model()
        self._init_csv_files()
        self._print_topology_summary()
        self._info("CONTROLLER_READY | TCP/UDP/ICMP telemetry active | ARP forward-only")

    def _paint(self, text, color):
        return f"{color}{text}{self.RESET}"

    def _get_risk_emoji(self, threat_score):
        if threat_score <= 5:
            return "🟢"
        if threat_score <= 25:
            return "🟡"
        if threat_score <= 55:
            return "🟠"
        return "🔴"

    def _ok(self, message):
        self.logger.info(self._paint(f"✔️ OK         | {message}", self.GREEN))

    def _info(self, message):
        self.logger.info(self._paint(f"✅ INFO       | {message}", self.GREEN))

    def _warn(self, message):
        self.logger.warning(self._paint(f"⚠️ WARN       | {message}", self.YELLOW))

    def _alert(self, message):
        self.logger.warning(self._paint(f"🚨 ALERT      | {message}", self.RED))

    def _mitigation(self, message):
        self.logger.warning(self._paint(f"🛡️ MITIGATION | {message}", self.MAGENTA))

    def _rate_limit_active(self, message):
        self.logger.info(self._paint(f"🔵 RL_ACTIVE  | {message}", self.CYAN))

    def _release(self, message):
        self.logger.info(self._paint(f"✔️ RELEASE    | {message}", self.DIM))

    def _startup_banner(self):
        self.logger.info(self._paint("=" * 90, self.CYAN))
        self.logger.info(self._paint("🔒 Ryu SDN ICMP Flood Forensic Controller vFinal", self.CYAN))
        self.logger.info(self._paint("📊 TCP/UDP/ICMP Telemetry | ARP Forward-Only | EWMA | OpenFlow Meter", self.CYAN))
        self.logger.info(self._paint("🧾 Single-Line Forensic Console | Noisy WARN/ALERT | CSV Evidence Ready", self.CYAN))
        self.logger.info(self._paint("=" * 90, self.CYAN))

    def _print_topology_summary(self):
        self.logger.info(self._paint("📍 TOPOLOGY | Core=s1 | Access=s2-s6 | Hosts=25 | Victim=10.0.0.25", self.CYAN))
        for ip, hostname in self.ATTACKER_IPS.items():
            _, seg = self.ATTACKER_SEGMENTS[ip]
            self.logger.info(self._paint(f"🔴 ATTACKER   | {ip} ({hostname}) | Segment={seg}", self.RED))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self._ok(f"SWITCH_CONNECTED | dpid={datapath.id} | name={self.SWITCH_DPID_MAP.get(datapath.id, 'unknown')}")
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self._warn(f"SWITCH_DISCONNECTED | dpid={datapath.id}")

    def _load_model(self):
        for model_path in self.model_candidates:
            if os.path.exists(model_path):
                try:
                    self.model = joblib.load(model_path)
                    self.feature_names = list(getattr(self.model, "feature_names_in_", []))
                    self._ok(f"SVM_LOADED | path={model_path}")
                    return
                except Exception as e:
                    self.logger.error("Failed to load model %s: %s", model_path, e)

        self.model = None
        self.feature_names = []
        self._warn("SVM_NOT_LOADED | Detection=threshold+EWMA")

    def _ensure_csv_with_header(self, path, header):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if (not os.path.exists(path)) or os.path.getsize(path) == 0:
            with open(path, "w", newline="") as f:
                csv.writer(f).writerow(header)

    def _init_csv_files(self):
        traffic_header = [
            "timestamp", "severity", "event_type", "detection_status",
            "mitigation_status", "session_id", "protocol_name",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "src_mac", "dst_mac", "dpid", "dpid_name",
            "in_port", "out_port", "packet_rate", "packet_count",
            "threat_score", "attack_type", "final_prediction",
            "attacker_segment", "meter_id", "event_note",
        ]

        mitigation_header = [
            "timestamp", "src_ip", "attacker_hostname",
            "dpid", "dpid_name", "segment_description",
            "action", "reason", "meter_id", "limit_pps",
            "idle_timeout", "hard_timeout", "note",
        ]

        self._ensure_csv_with_header(self.traffic_analysis_path, traffic_header)
        self._ensure_csv_with_header(self.mitigation_log_path, mitigation_header)
        self._ok("CSV_READY | traffic_analysis.csv | mitigation_events.csv")

    def _append_csv(self, path, row):
        with open(path, "a", newline="") as f:
            csv.writer(f).writerow(row)

    def _get_protocol_name(self, eth_type, ip_proto):
        if eth_type == 0x0806:
            return "ARP"
        if eth_type == 0x0800:
            if ip_proto == 1:
                return "ICMP"
            if ip_proto == 6:
                return "TCP"
            if ip_proto == 17:
                return "UDP"
        return "OTHER"

    def _get_tcp_udp_ports(self, pkt):
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            return tcp_pkt.src_port, tcp_pkt.dst_port

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            return udp_pkt.src_port, udp_pkt.dst_port

        return "", ""

    def _ip_to_number(self, ip_addr):
        if not ip_addr or ip_addr == "0.0.0.0":
            return 0.0
        try:
            parts = ip_addr.split(".")
            return float(
                (int(parts[0]) << 24)
                + (int(parts[1]) << 16)
                + (int(parts[2]) << 8)
                + int(parts[3])
            )
        except Exception:
            return 0.0

    def _mac_to_number(self, mac_addr):
        if not mac_addr:
            return 0.0
        try:
            return float(int(mac_addr.replace(":", ""), 16))
        except Exception:
            return 0.0

    def _build_feature_dataframe(self, dpid, src_mac, dst_mac, src_ip, dst_ip,
                                  eth_type, ip_proto, icmp_type, in_port,
                                  out_port, packet_rate):
        values = {
            "timestamp": 0.0,
            "dpid": float(dpid),
            "src_mac": self._mac_to_number(src_mac),
            "dst_mac": self._mac_to_number(dst_mac),
            "src_ip": self._ip_to_number(src_ip),
            "dst_ip": self._ip_to_number(dst_ip),
            "eth_type": float(eth_type),
            "ip_proto": float(ip_proto),
            "icmp_type": float(icmp_type),
            "in_port": float(in_port),
            "out_port": float(out_port) if isinstance(out_port, (int, float)) else 0.0,
            "packet_rate": float(packet_rate),
            "prediction": 0.0,
            "label": 0.0,
        }

        if self.feature_names:
            row = {name: values.get(name, 0.0) for name in self.feature_names}
            return pd.DataFrame([row], columns=self.feature_names)

        fallback_order = [
            "dpid", "src_mac", "dst_mac", "src_ip", "dst_ip",
            "eth_type", "ip_proto", "icmp_type", "in_port",
            "out_port", "packet_rate", "prediction",
        ]
        row = {name: values[name] for name in fallback_order}
        return pd.DataFrame([row], columns=fallback_order)

    def _predict_traffic(self, features_df):
        if self.model is None:
            return 0
        try:
            return int(self.model.predict(features_df)[0])
        except Exception as e:
            self.logger.error("Prediction failed: %s", e)
            return 0

    def _get_session_id(self, src_ip, dst_ip, protocol_name="", src_port="", dst_port=""):
        if protocol_name in ["TCP", "UDP"] and src_port and dst_port:
            return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol_name}"
        return f"{src_ip}->{dst_ip}:{protocol_name}"

    def _get_packet_rate(self, session_id):
        now = time.time()
        q = self.session_packet_times[session_id]
        q.append(now)

        while q and (now - q[0] > self.rate_window_seconds):
            q.popleft()

        raw_rate = float(len(q)) / self.rate_window_seconds
        prev = self.ewma_rates[session_id]
        smoothed = self.ewma_alpha * raw_rate + (1.0 - self.ewma_alpha) * prev
        self.ewma_rates[session_id] = smoothed

        return smoothed

    def _update_session_stats(self, session_id, timestamp_str):
        session = self.session_stats[session_id]
        if session["start_time"] is None:
            session["start_time"] = timestamp_str
        session["last_seen"] = timestamp_str
        session["packet_count"] += 1
        return session

    def _apply_prediction_guard(self, svm_prediction, packet_rate):
        if packet_rate < self.warning_rate_threshold:
            return 0

        if self.model is None:
            return 1 if packet_rate >= self.attack_rate_threshold else 0

        return int(svm_prediction)

    def _calculate_threat_score(self, packet_rate, final_prediction):
        if final_prediction == 0:
            if packet_rate >= 40:
                return 25
            if packet_rate >= 20:
                return 12
            return 5

        if packet_rate >= 350:
            return 95
        if packet_rate >= 250:
            return 85
        if packet_rate >= 150:
            return 70
        if packet_rate >= 100:
            return 55
        return 40

    def _get_attack_type(self, protocol_name, final_prediction, mitigation_active):
        if protocol_name != "ICMP":
            return "BENIGN_TRAFFIC"
        if mitigation_active:
            return "ICMP_FLOOD_LIMITED"
        return "ICMP_FLOOD" if final_prediction == 1 else "BENIGN_ICMP"

    def _get_attacker_segment(self, src_ip):
        if src_ip in self.ATTACKER_SEGMENTS:
            _, segment_desc = self.ATTACKER_SEGMENTS[src_ip]
            return segment_desc
        return "NORMAL_HOST"

    def _update_detection_state(self, session_id, final_prediction, packet_rate, mitigation_active):
        now = time.time()
        state = self.session_detection_state[session_id]
        state["last_event_time"] = now

        if mitigation_active:
            state["status"] = "RATE_LIMIT_ACTIVE"
            return state

        if final_prediction == 0:
            if packet_rate >= self.warning_rate_threshold:
                if state["warning_since"] is None:
                    state["warning_since"] = now
                state["status"] = "WARNING"
            else:
                state["status"] = "NORMAL"
                state["warning_since"] = None
                state["confirmed_since"] = None
                state["alert_first_seen"] = None
            return state

        if state["warning_since"] is None:
            state["warning_since"] = now

        elapsed = now - state["warning_since"]

        if elapsed >= self.confirmation_seconds:
            state["status"] = "ATTACK_CONFIRMED"
            if state["confirmed_since"] is None:
                state["confirmed_since"] = now
            if state["alert_first_seen"] is None:
                state["alert_first_seen"] = now
        else:
            state["status"] = "WARNING"

        return state

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _send_packet_out(self, datapath, msg, in_port, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _meter_id_for_ip(self, src_ip):
        try:
            return self.meter_id_base + int(src_ip.split(".")[-1])
        except Exception:
            return self.meter_id_base + 999

    def _delete_meter_if_exists(self, datapath, meter_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        try:
            mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                flags=ofproto.OFPMF_PKTPS,
                meter_id=meter_id,
                bands=[],
            )
            datapath.send_msg(mod)
        except Exception as e:
            self.logger.debug("Delete meter ignored for meter_id=%s: %s", meter_id, e)

    def _add_rate_limit_meter(self, datapath, meter_id, rate_pps):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        band = parser.OFPMeterBandDrop(rate=rate_pps, burst_size=0)
        mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_PKTPS,
            meter_id=meter_id,
            bands=[band],
        )
        datapath.send_msg(mod)

    def _add_rate_limited_flow(self, datapath, src_ip, out_port, meter_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if out_port == ofproto.OFPP_FLOOD:
            self._warn(f"MITIGATION_FLOW_SKIPPED | {src_ip} | out_port=FLOOD | Meter installed, retry on learned packet")
            return

        match = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=1,
            ipv4_src=src_ip,
            ipv4_dst=self.VICTIM_IP,
        )
        actions = [parser.OFPActionOutput(out_port)]

        self.add_flow(
            datapath=datapath,
            priority=200,
            match=match,
            actions=actions,
            idle_timeout=self.rate_limit_idle_timeout,
            hard_timeout=self.rate_limit_hard_timeout,
            meter_id=meter_id,
        )

    def _resolve_mitigation_datapath(self, src_ip, fallback_datapath):
        if src_ip in self.ATTACKER_SEGMENTS:
            target_dpid, _ = self.ATTACKER_SEGMENTS[src_ip]
            target_dp = self.datapaths.get(target_dpid)
            if target_dp is not None:
                return target_dp, target_dpid
        return fallback_datapath, fallback_datapath.id

    def _get_adaptive_rate_limit(self, packet_rate):
        if packet_rate >= 300:
            return self.heavy_limit_pps
        if packet_rate >= 150:
            return self.medium_limit_pps
        return self.light_limit_pps

    def _get_adaptive_label(self, packet_rate):
        if packet_rate >= 300:
            return "HEAVY"
        if packet_rate >= 150:
            return "MEDIUM"
        return "LIGHT"

    def _mitigation_worker(self):
        while True:
            try:
                task = self._mitigation_queue.get()
                if task is None:
                    break

                action = task["action"]
                datapath = task["datapath"]
                meter_id = task["meter_id"]
                src_ip = task.get("src_ip")
                out_port = task.get("out_port")
                rate_pps = task.get("rate_pps")
                now_str = task.get("now_str")
                segment_desc = task.get("segment_desc", "")
                hostname = task.get("hostname", "UNKNOWN")
                target_dpid = task.get("target_dpid")
                adaptive_label = task.get("adaptive_label", "")

                if action == "ADD":
                    self._delete_meter_if_exists(datapath, meter_id)
                    hub.sleep(0.05)

                    self._add_rate_limit_meter(datapath, meter_id, rate_pps)
                    hub.sleep(0.05)

                    self._add_rate_limited_flow(datapath, src_ip, out_port, meter_id)

                    state = self.active_mitigations[src_ip]
                    state["active"] = True
                    state["start_time"] = time.time()
                    state["last_applied_dpid"] = target_dpid
                    state["segment_description"] = segment_desc
                    state["reason"] = "ATTACK_CONFIRMED_DELAY_PASSED"
                    state["meter_id"] = meter_id
                    state["limit_pps"] = rate_pps

                    self._append_csv(
                        self.mitigation_log_path,
                        [
                            now_str, src_ip, hostname,
                            target_dpid,
                            self.SWITCH_DPID_MAP.get(target_dpid, "unknown"),
                            segment_desc, "RATE_LIMIT_ICMP",
                            "ATTACK_CONFIRMED_DELAY_PASSED",
                            meter_id, rate_pps,
                            self.rate_limit_idle_timeout,
                            self.rate_limit_hard_timeout,
                            f"Adaptive ICMP rate limiting activated [{adaptive_label}]",
                        ],
                    )

                    self._mitigation(
                        f"{src_ip} ({hostname}) → {self.VICTIM_IP} | "
                        f"Segment={segment_desc} | Meter={meter_id} | "
                        f"Limit={rate_pps}pps | Mode={adaptive_label} | ACTIVE"
                    )

                elif action == "DELETE":
                    self._delete_meter_if_exists(datapath, meter_id)

                    limit_pps = task.get("limit_pps", "")
                    self._append_csv(
                        self.mitigation_log_path,
                        [
                            now_str, src_ip, hostname,
                            target_dpid,
                            self.SWITCH_DPID_MAP.get(target_dpid, "unknown") if target_dpid else "",
                            segment_desc, "RELEASE_METER",
                            "HARD_TIMEOUT_EXPIRED",
                            meter_id, limit_pps,
                            self.rate_limit_idle_timeout,
                            self.rate_limit_hard_timeout,
                            "Mitigation released; network returned to normal",
                        ],
                    )

                    self._release(f"{src_ip} | Traffic NORMALIZED | Meter={meter_id} | Mitigation Removed")

            except Exception as e:
                self.logger.error("Mitigation worker error: %s", e)

    def _should_log_alert(self, src_ip):
        now = time.time()
        if (now - self.last_alert_log_time[src_ip]) >= self.alert_log_interval:
            self.last_alert_log_time[src_ip] = now
            return True
        return False

    def _should_log_warning(self, src_ip):
        now = time.time()
        if (now - self.last_warning_log_time[src_ip]) >= self.warning_log_interval:
            self.last_warning_log_time[src_ip] = now
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

    def _should_log_limited(self, src_ip):
        now = time.time()
        if (now - self.last_limited_log_time[src_ip]) >= self.limited_log_interval:
            self.last_limited_log_time[src_ip] = now
            return True
        return False

    def _should_log_limited_csv(self, src_ip):
        now = time.time()
        if (now - self.last_limited_csv_time[src_ip]) >= self.limited_csv_interval:
            self.last_limited_csv_time[src_ip] = now
            return True
        return False

    def _cleanup_stale_sessions(self):
        now = time.time()
        stale = []

        for sid, q in self.session_packet_times.items():
            if not q or (now - q[-1]) > self._session_max_age:
                stale.append(sid)

        for sid in stale:
            self.session_packet_times.pop(sid, None)
            self.session_stats.pop(sid, None)
            self.session_detection_state.pop(sid, None)
            self.ewma_rates.pop(sid, None)

        if stale:
            self.logger.debug("Session cleanup: %d stale sessions removed", len(stale))

    def _apply_mitigation_if_needed(self, datapath, src_ip, out_port, packet_rate):
        target_dp, target_dpid = self._resolve_mitigation_datapath(src_ip, datapath)
        state = self.active_mitigations[src_ip]

        if state["active"]:
            return "ACTIVE", state.get("meter_id")

        meter_id = self._meter_id_for_ip(src_ip)
        adaptive_limit = self._get_adaptive_rate_limit(packet_rate)
        adaptive_label = self._get_adaptive_label(packet_rate)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        _, segment_desc = self.ATTACKER_SEGMENTS.get(src_ip, (target_dpid, "UNKNOWN_SEGMENT"))
        hostname = self.ATTACKER_IPS.get(src_ip, "UNKNOWN")

        self._mitigation_queue.put({
            "action": "ADD",
            "datapath": target_dp,
            "meter_id": meter_id,
            "src_ip": src_ip,
            "out_port": out_port,
            "rate_pps": adaptive_limit,
            "now_str": now_str,
            "segment_desc": segment_desc,
            "hostname": hostname,
            "target_dpid": target_dpid,
            "adaptive_label": adaptive_label,
        })

        state["active"] = True
        state["meter_id"] = meter_id
        state["limit_pps"] = adaptive_limit
        state["start_time"] = time.time()
        state["last_applied_dpid"] = target_dpid
        state["segment_description"] = segment_desc

        return "ACTIVE", meter_id

    def _refresh_mitigation_state(self, src_ip):
        state = self.active_mitigations[src_ip]

        if not state["active"]:
            return "OFF", None

        if state["start_time"] is None:
            return "OFF", None

        elapsed = time.time() - state["start_time"]

        if elapsed >= self.rate_limit_hard_timeout:
            meter_id = state.get("meter_id")
            target_dpid = state.get("last_applied_dpid")
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            hostname = self.ATTACKER_IPS.get(src_ip, "UNKNOWN")
            segment_desc = state.get("segment_description") or self._get_attacker_segment(src_ip)

            if meter_id and target_dpid and target_dpid in self.datapaths:
                self._mitigation_queue.put({
                    "action": "DELETE",
                    "datapath": self.datapaths[target_dpid],
                    "meter_id": meter_id,
                    "src_ip": src_ip,
                    "hostname": hostname,
                    "target_dpid": target_dpid,
                    "segment_desc": segment_desc,
                    "limit_pps": state.get("limit_pps", ""),
                    "now_str": now_str,
                })

            state.update({
                "active": False,
                "start_time": None,
                "last_applied_dpid": None,
                "segment_description": None,
                "reason": None,
                "meter_id": None,
                "limit_pps": None,
            })

            self.last_alert_log_time[src_ip] = 0.0
            self.last_limited_log_time[src_ip] = 0.0
            self.last_limited_csv_time[src_ip] = 0.0

            return "OFF", None

        return "ACTIVE", state.get("meter_id")

    def _should_activate_mitigation(self, session_id):
        state = self.session_detection_state[session_id]

        if state["status"] != "ATTACK_CONFIRMED":
            return False

        if state["alert_first_seen"] is None:
            return False

        return (time.time() - state["alert_first_seen"]) >= self.mitigation_delay_after_alert

    def _get_countdown_seconds(self, session_id):
        state = self.session_detection_state[session_id]

        if state["alert_first_seen"] is None:
            return int(self.mitigation_delay_after_alert)

        elapsed = time.time() - state["alert_first_seen"]
        remaining = max(0, self.mitigation_delay_after_alert - elapsed)

        return int(remaining)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        icmp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        icmp_actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 100, icmp_match, icmp_actions)

        miss_match = parser.OFPMatch()
        miss_actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, miss_match, miss_actions)

        dpid_name = self.SWITCH_DPID_MAP.get(datapath.id, "unknown")
        self._ok(f"FLOW_INSTALLED | dpid={datapath.id} | name={dpid_name} | ICMP mirrored + table-miss enabled")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        now = time.time()
        if (now - self._last_cleanup_time) >= self._cleanup_interval:
            self._cleanup_stale_sessions()
            self._last_cleanup_time = now

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == 0x88cc:
            return

        dpid = datapath.id
        dpid_name = self.SWITCH_DPID_MAP.get(dpid, "unknown")
        src_mac = eth.src
        dst_mac = eth.dst

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        arp_pkt = pkt.get_protocol(arp.arp)

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath, 10, match, actions,
                    buffer_id=msg.buffer_id,
                    idle_timeout=30,
                    hard_timeout=60,
                )
            else:
                self.add_flow(
                    datapath, 10, match, actions,
                    idle_timeout=30,
                    hard_timeout=60,
                )

        # ARP forward-only: tidak masuk CSV dan tidak tampil console.
        if arp_pkt is not None:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # TCP/UDP baseline telemetry.
        if icmp_pkt is None:
            if ip_pkt is not None:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                protocol_name = self._get_protocol_name(eth.ethertype, ip_pkt.proto)
                src_port, dst_port = self._get_tcp_udp_ports(pkt)

                if protocol_name in ["TCP", "UDP"]:
                    session_id = self._get_session_id(
                        src_ip, dst_ip, protocol_name, src_port, dst_port
                    )

                    self._append_csv(
                        self.traffic_analysis_path,
                        [
                            timestamp, "INFO", "NORMAL", "NORMAL", "OFF",
                            session_id, protocol_name,
                            src_ip, dst_ip,
                            src_port if src_port else "",
                            dst_port if dst_port else "",
                            src_mac, dst_mac,
                            dpid, dpid_name,
                            in_port,
                            out_port if isinstance(out_port, int) else 0,
                            0.0,
                            1,
                            5,
                            "BENIGN_TRAFFIC",
                            0,
                            "NORMAL_HOST",
                            "",
                            "baseline_normal_traffic",
                        ],
                    )

                    key = f"{protocol_name}:{src_ip}->{dst_ip}:{dst_port}"
                    if self._should_log_baseline(key):
                        self._info(
                            f"{protocol_name} NORMAL | "
                            f"{src_ip}:{src_port or '-'} → {dst_ip}:{dst_port or '-'} | "
                            f"Risk=🟢5 | BASELINE"
                        )

            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # ICMP detection.
        if ip_pkt is None:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        if icmp_pkt.type != 8:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        session_id = self._get_session_id(src_ip, dst_ip, "ICMP")
        packet_rate = self._get_packet_rate(session_id)

        # Semua ICMP normal boleh tampil agar pingall terlihat natural.
        # Tetapi detection dan mitigation tetap hanya untuk traffic menuju victim h25.
        is_victim_traffic = (dst_ip == self.VICTIM_IP)

        if not is_victim_traffic:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            session = self._update_session_stats(session_id, timestamp)
            packet_count = session["packet_count"]

            traffic_row = [
                timestamp,
                "INFO",
                "NORMAL",
                "NORMAL",
                "OFF",
                session_id,
                "ICMP",
                src_ip,
                dst_ip,
                "",
                "",
                src_mac,
                dst_mac,
                dpid,
                dpid_name,
                in_port,
                out_port if isinstance(out_port, int) else 0,
                round(packet_rate, 4),
                packet_count,
                5,
                "BENIGN_ICMP",
                0,
                "NORMAL_HOST",
                "",
                "normal_icmp_non_victim",
            ]
            self._append_csv(self.traffic_analysis_path, traffic_row)

            key = f"ICMP:{src_ip}->{dst_ip}"
            if self._should_log_info(key):
                self._info(
                    f"ICMP NORMAL | {src_ip} → {dst_ip} | "
                    f"{packet_rate:.2f}pps | Risk=🟢5"
                )

            self._send_packet_out(datapath, msg, in_port, actions)
            return

        features_df = self._build_feature_dataframe(
            dpid=dpid,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            eth_type=eth.ethertype,
            ip_proto=ip_pkt.proto,
            icmp_type=icmp_pkt.type,
            in_port=in_port,
            out_port=out_port if isinstance(out_port, int) else 0,
            packet_rate=packet_rate,
        )

        svm_prediction = self._predict_traffic(features_df)
        final_prediction = self._apply_prediction_guard(svm_prediction, packet_rate)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        session = self._update_session_stats(session_id, timestamp)
        packet_count = session["packet_count"]

        mitigation_status, current_meter_id = self._refresh_mitigation_state(src_ip)
        mitigation_active = mitigation_status == "ACTIVE"

        detection_state = self._update_detection_state(
            session_id, final_prediction, packet_rate, mitigation_active
        )
        detection_status = detection_state["status"]

        if mitigation_active:
            final_prediction_for_log = 0
            severity = "INFO"
            event_type = "LIMITED"
            event_note = "rate_limit_active"
        elif detection_status == "ATTACK_CONFIRMED":
            final_prediction_for_log = final_prediction
            severity = "ALERT"
            event_type = "ATTACK"
            event_note = "icmp_flood_confirmed"
        elif detection_status == "WARNING":
            final_prediction_for_log = final_prediction
            severity = "WARNING"
            event_type = "SUSPICIOUS"
            event_note = "icmp_rate_warning"
        else:
            final_prediction_for_log = final_prediction
            severity = "INFO"
            event_type = "NORMAL"
            event_note = "normal_icmp_to_victim"

        threat_score = self._calculate_threat_score(packet_rate, final_prediction_for_log)
        risk_emoji = self._get_risk_emoji(threat_score)
        attack_type = self._get_attack_type("ICMP", final_prediction_for_log, mitigation_active)
        attacker_segment = self._get_attacker_segment(src_ip)

        traffic_row = [
            timestamp,
            severity,
            event_type,
            detection_status,
            mitigation_status,
            session_id,
            "ICMP",
            src_ip,
            dst_ip,
            "",
            "",
            src_mac,
            dst_mac,
            dpid,
            dpid_name,
            in_port,
            out_port if isinstance(out_port, int) else 0,
            round(packet_rate, 4),
            packet_count,
            threat_score,
            attack_type,
            final_prediction_for_log,
            attacker_segment,
            current_meter_id if current_meter_id is not None else "",
            event_note,
        ]

        if mitigation_active:
            if self._should_log_limited_csv(src_ip):
                self._append_csv(self.traffic_analysis_path, traffic_row)
        else:
            self._append_csv(self.traffic_analysis_path, traffic_row)

        if mitigation_active:
            if self._should_log_limited(src_ip):
                limit_pps = self.active_mitigations[src_ip].get("limit_pps") or ""
                self._rate_limit_active(
                    f"{src_ip} → {dst_ip} | "
                    f"Meter={current_meter_id} | Limit={limit_pps}pps | "
                    f"Current={packet_rate:.2f}pps | Risk={risk_emoji}{threat_score} | CONTROLLED"
                )

        elif detection_status == "ATTACK_CONFIRMED":
            if self._should_log_alert(src_ip):
                countdown = self._get_countdown_seconds(session_id)
                if countdown > 0:
                    status_txt = f"MITIGATING_IN_{countdown}s"
                else:
                    status_txt = "ACTIVATING_MITIGATION"

                self._alert(
                    f"ICMP FLOOD | {src_ip} → {dst_ip} | "
                    f"{packet_rate:.2f}pps | Risk={risk_emoji}{threat_score} | "
                    f"Packets={packet_count} | ATTACK_CONFIRMED | {status_txt}"
                )

            if self._should_activate_mitigation(session_id):
                self._apply_mitigation_if_needed(datapath, src_ip, out_port, packet_rate)

        elif detection_status == "WARNING":
            if self._should_log_warning(src_ip):
                ratio = packet_rate / float(self.warning_rate_threshold)

                self._warn(
                    f"ICMP SUSPECT | {src_ip} → {dst_ip} | "
                    f"{packet_rate:.2f}pps | Threshold={self.warning_rate_threshold:.0f}pps | "
                    f"Ratio={ratio:.1f}x | Risk={risk_emoji}{threat_score} | MONITORING"
                )

        else:
            key = f"ICMP:{src_ip}->{dst_ip}"
            if self._should_log_info(key):
                self._info(
                    f"ICMP NORMAL | {src_ip} → {dst_ip} | "
                    f"{packet_rate:.2f}pps | Risk={risk_emoji}{threat_score}"
                )

        self._send_packet_out(datapath, msg, in_port, actions)
