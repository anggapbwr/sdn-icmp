#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import time
import numpy as np
import warnings
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

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

    MITIGATION_HARD_TIMEOUT = 300
    MITIGATION_IDLE_TIMEOUT = 0

    # PATCH: idle_timeout untuk flow forwarding non-ICMP (TCP/UDP/ARP).
    # hard_timeout SENGAJA 0 (tidak pernah expired paksa) supaya transfer
    # panjang (mis. nc 100KB+, curl berkali-kali) tidak terputus tengah
    # jalan hanya karena flow-nya "kadaluarsa" walau traffic masih aktif.
    # idle_timeout tetap ada supaya flow yang benar-benar sudah tidak
    # dipakai (tidak ada traffic) akhirnya dibersihkan otomatis oleh OVS.
    FORWARDING_IDLE_TIMEOUT = 60
    FORWARDING_HARD_TIMEOUT = 0

    # PATCH: idle_timeout untuk flow ARP permanen per pasangan host, supaya
    # ARP tidak selalu nyangkut ke controller berulang-ulang (sebelumnya
    # SEMUA paket ARP di-packet_out lewat controller tanpa pernah dipasang
    # flow, sehingga ARP re-trigger terus-menerus dan mendominasi traffic
    # capture, bukan cuma sekali di awal seperti pada jaringan normal).
    ARP_FLOW_IDLE_TIMEOUT = 120
    ARP_FLOW_HARD_TIMEOUT = 0

    def __init__(self, *args, **kwargs):
        super(MonitorSwitch13, self).__init__(*args, **kwargs)

        base_candidates = [
            "/home/kali/sdn-icmp",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        ]
        self.base_dir = next((p for p in base_candidates if os.path.isdir(p)), base_candidates[-1])
        self.logs_dir   = os.path.join(self.base_dir, "logs")

        self.traffic_analysis_path = os.path.join(self.logs_dir, "traffic_analysis.csv")
        self.mitigation_log_path   = os.path.join(self.logs_dir, "mitigation_events.csv")

        self.mac_to_port = defaultdict(dict)
        self.datapaths   = {}

        self.rate_window_seconds          = 1.0
        self.warning_rate_threshold       = 10.0
        self.attack_rate_threshold        = 25.0
        # NOTE: confirmation_seconds sudah TIDAK dipakai di alur manapun sejak
        # SVM dihapus (dulu bagian dari kondisi svm_prediction==1 AND
        # elapsed_warning>=confirmation_seconds). Dibiarkan ada (bukan
        # dihapus) supaya tidak mengubah signature/config tanpa konfirmasi —
        # aman dihapus kapan saja karena tidak direferensikan di kode manapun.
        self.confirmation_seconds         = 5.0
        self.mitigation_delay_after_alert = 8.0

        # Jalankan dengan: DISABLE_MITIGATION=1 ryu-manager controller/controller.py
        self.disable_mitigation = os.getenv("DISABLE_MITIGATION", "0").lower() in ("1", "true", "yes", "on")
        # UPDATED: EWMA dihapus. Rate yang dipakai untuk keputusan & logging
        # sekarang murni raw_rate (sliding window 1 detik), tanpa smoothing.
        # Alasan: skenario pengujian pakai attacker dengan rate konsisten
        # (hping3 -i u1000), sehingga smoothing tidak memberi manfaat berarti
        # dan justru menimbulkan delay deteksi serta gap antara nilai rate
        # yang dicatat di CSV dengan nilai yang menjadi dasar keputusan —
        # penting untuk transparansi/auditability hasil pengujian.

        self.alert_log_interval    = 0.001   # ~1000 log/detik (enterprise-grade)
        self.warning_log_interval  = 0.001   # ~1000 log/detik
        self.info_log_interval     = 0.5     # 2 log/detik (info tidak perlu sepadat attack)
        self.drop_log_interval     = 1.0     # 1 log/detik

        self.last_alert_log_time   = defaultdict(float)
        self.last_warning_log_time = defaultdict(float)
        self.last_info_log_time    = defaultdict(float)
        self.last_drop_log_time    = defaultdict(float)

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

        self._last_cleanup_time  = time.time()
        self._cleanup_interval   = 120.0
        self._session_max_age    = 300.0

        self._startup_banner()
        self._init_csv_files()
        self._print_topology_summary()
        self._info("CONTROLLER_READY | Drop-based mitigation | 3-phase scenario ready")

    def _paint(self, text, color):
        return f"{color}{text}{self.RESET}"

    def _get_risk_emoji(self, threat_score):
        if threat_score <= 5:
            return "🟢"
        if threat_score < 40:
            return "🟡"
        if threat_score < 60:
            return "🟠"
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
        # DEPRECATED: dipertahankan untuk kompatibilitas, tapi event mitigasi
        # sekarang dicetak lewat _log_mitigation_event() dengan format seragam
        # (DROP_INSTALLED/DROP_EXPIRED), bukan lewat method ini lagi.
        self.logger.warning(self._paint(f"🛡️ MITIGATION | {msg}", self.MAGENTA))

    def _release(self, msg):
        # DEPRECATED: sama seperti _mitigation() di atas, digantikan
        # _log_mitigation_event("DROP_EXPIRED", ...).
        self.logger.info(self._paint(f"✔️ RELEASE    | {msg}", self.DIM))

    # -------------------------------------------------------------------
    # FORMAT LOG SERAGAM
    #
    # Ada 2 jenis log yang sifatnya beda, sengaja tidak dipaksa satu bentuk:
    #
    # 1) STATUS TRAFFIC (NORMAL/WARNING/ATTACK) — dipanggil lewat
    #    _log_traffic_status(). Berulang tiap paket diproses, SELALU py
    #    Src/Dst/Rate/Risk/Phase karena memang ada paket nyata yang diukur.
    #
    # 2) EVENT MITIGASI (DROP_INSTALLED/DROP_EXPIRED) — dipanggil lewat
    #    _log_mitigation_event(). Sesaat, cuma 2x per attacker per siklus
    #    drop (pasang & expired). TIDAK ada Rate/Risk karena tidak ada
    #    paket yang sedang diukur di momen itu (attacker sudah tidak
    #    terlihat controller selama drop rule aktif).
    #
    # Jangan gabungkan keduanya ke satu template — itu yang bikin log lama
    # membingungkan (Risk= muncul di baris mitigasi padahal tidak relevan).
    # -------------------------------------------------------------------

    def _log_traffic_status(self, status, src_ip, dst_ip, rate, threat_score, phase,
                             protocol=None, src_port=None, dst_port=None):
        """
        Satu-satunya jalur cetak untuk status traffic NORMAL/WARNING/ATTACK.
        Formatnya identik untuk ketiganya, cuma icon/warna & nilai field beda.
        """
        risk_emoji = self._get_risk_emoji(threat_score)

        if protocol and protocol in ("TCP", "UDP") and src_port and dst_port:
            endpoint = f"Src={src_ip}:{src_port} → Dst={dst_ip}:{dst_port} [{protocol}]"
        else:
            endpoint = f"Src={src_ip} → Dst={dst_ip}"

        line = (
            f"{endpoint} | Rate={rate:.2f}pps | "
            f"Risk={risk_emoji}{threat_score} | Phase={phase}"
        )

        if status == "NORMAL":
            self.logger.info(self._paint(f"✅ NORMAL     | {line}", self.GREEN))
        elif status == "WARNING":
            self.logger.warning(self._paint(f"⚠️ WARNING    | {line}", self.YELLOW))
        elif status == "ATTACK":
            self.logger.warning(self._paint(f"🚨 ATTACK     | {line}", self.RED))

    def _log_mitigation_event(self, action, src_ip, hostname, dst_ip, switch_name=None,
                               hard_timeout=None, phase=None):
        """
        Satu-satunya jalur cetak untuk event mitigasi (bukan status traffic).
        action: "DROP_INSTALLED" atau "DROP_EXPIRED".
        """
        if action == "DROP_INSTALLED":
            self.logger.warning(self._paint(
                f"🛡️ MITIGATION | DROP_INSTALLED | Src={src_ip} ({hostname}) → Dst={dst_ip} | "
                f"Switch={switch_name} | HardTimeout={hard_timeout}s",
                self.MAGENTA,
            ))
        elif action == "DROP_EXPIRED":
            self.logger.info(self._paint(
                f"✔️ RELEASE    | DROP_EXPIRED | Src={src_ip} ({hostname}) → Dst={dst_ip} | Phase={phase}",
                self.DIM,
            ))

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

    def _should_log_drop(self, key):
        now = time.time()
        if (now - self.last_drop_log_time[key]) >= self.drop_log_interval:
            self.last_drop_log_time[key] = now
            return True
        return False

    def _startup_banner(self):
        self.logger.info(self._paint("=" * 90, self.CYAN))
        self.logger.info(self._paint("🔒 Ryu SDN ICMP Flood Forensic Controller — Final (Drop-Based)", self.CYAN))
        self.logger.info(self._paint("📊 3-Phase scenario: NORMAL → ATTACK → MITIGATED", self.CYAN))
        self.logger.info(self._paint("🧾 Baseline ping always logged to CSV | Clear cliff on grafik", self.CYAN))
        self.logger.info(self._paint("📈 Detection=raw rate threshold (no SVM, no EWMA)", self.CYAN))
        if self.disable_mitigation:
            self.logger.warning(self._paint(
                "⚠️  MITIGATION DISABLED — mode deteksi-saja (DISABLE_MITIGATION=1)", self.YELLOW))
        else:
            self.logger.info(self._paint("🛡️  Mitigation ENABLED — mode normal", self.CYAN))
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
            self._ok(f"SWITCH_CONNECTED | dpid={datapath.id} | name={self.SWITCH_DPID_MAP.get(datapath.id,'unknown')}")
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self._warn(f"SWITCH_DISCONNECTED | dpid={datapath.id}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.add_flow(datapath, 100,
            parser.OFPMatch(eth_type=0x0800, ip_proto=1),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

        self.add_flow(datapath, 0,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

        self._ok(f"FLOW_INSTALLED | dpid={datapath.id} | {self.SWITCH_DPID_MAP.get(datapath.id,'unknown')}")

    def _ensure_csv_with_header(self, path, header):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if (not os.path.exists(path)) or os.path.getsize(path) == 0:
            with open(path, "w", newline="") as f:
                csv.writer(f).writerow(header)

    def _init_csv_files(self):
        # UPDATED: kolom SVM (final_prediction) dihapus. 12 kolom total.
        traffic_header = [
            "timestamp", "src_ip", "dst_ip", "protocol_name", "session_id",
            "detection_status", "phase",
            "packet_rate", "packet_count", "threat_score",
            "dpid_name", "event_note",
        ]

        mitigation_header = [
            "timestamp", "src_ip", "attacker_hostname",
            "dpid", "dpid_name", "segment_description",
            "action", "reason", "idle_timeout", "hard_timeout", "note",
        ]

        self._ensure_csv_with_header(self.traffic_analysis_path, traffic_header)
        self._ensure_csv_with_header(self.mitigation_log_path,   mitigation_header)
        self._ok("CSV_READY | traffic_analysis.csv (12 cols, no SVM) | mitigation_events.csv")

    def _append_csv(self, path, row):
        with open(path, "a", newline="") as f:
            csv.writer(f).writerow(row)

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

    def _lookup_attacker_mac(self, src_ip):
        if src_ip not in self.ATTACKER_IPS:
            return None
        try:
            host_number = int(src_ip.split(".")[-1])
            return f"00:00:00:00:00:{host_number:02x}"
        except Exception:
            return None

    def _classify_rate(self, packet_rate):
        """
        Pengganti _apply_prediction_guard (SVM dihapus).
        Klasifikasi murni berbasis threshold raw rate (tanpa EWMA):
          rate < warning_rate_threshold   -> 0 (NORMAL)
          rate >= attack_rate_threshold   -> 1 (ATTACK)
          di antara keduanya              -> 0 (masih WARNING, belum ATTACK;
                                                 status WARNING/ATTACK_CONFIRMED
                                                 tetap ditentukan di
                                                 _update_detection_state)
        """
        if packet_rate >= self.attack_rate_threshold:
            return 1
        return 0

    def _get_session_id(self, src_ip, dst_ip, protocol_name="", src_port="", dst_port=""):
        if protocol_name in ["TCP","UDP"] and src_port and dst_port:
            return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol_name}"
        return f"{src_ip}->{dst_ip}:{protocol_name}"

    def _get_session_window_features(self, session_id, packet_size):
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
        # EWMA dihapus — raw_rate langsung jadi satu-satunya basis keputusan
        # dan logging (lihat catatan di __init__).

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
            # Satu-satunya rate: dipakai untuk keputusan (_classify_rate,
            # _update_detection_state) MAUPUN untuk logging CSV/console.
            # Tidak ada lagi dua angka (ewma vs raw) yang bisa berbeda —
            # angka yang dicatat = angka yang memicu keputusan.
            "packet_rate":       raw_rate,
            "packet_count_1s":   packet_count_1s,
            "byte_count_1s":     byte_count_1s,
            "avg_pkt_size":      avg_pkt_size,
            "pkt_size_std":      pkt_size_std,
            "inter_arrival_std": inter_arrival_std,
        }

    def _update_session_stats(self, session_id, timestamp_str):
        s = self.session_stats[session_id]
        if s["start_time"] is None: s["start_time"] = timestamp_str
        s["last_seen"]     = timestamp_str
        s["packet_count"] += 1
        return s

    def _calculate_threat_score(self, packet_rate, final_prediction):
        # final_prediction sekarang murni hasil _classify_rate (bukan SVM lagi)
        if final_prediction == 0:
            if packet_rate >= self.attack_rate_threshold:
                return 40
            if packet_rate >= self.warning_rate_threshold:
                return 25
            return 5

        if packet_rate >= 400:
            return 95
        if packet_rate >= 200:
            return 85
        if packet_rate >= 100:
            return 75
        if packet_rate >= self.attack_rate_threshold:
            return 65
        return 55

    def _get_attacker_segment(self, src_ip):
        if src_ip in self.ATTACKER_SEGMENTS:
            _, seg = self.ATTACKER_SEGMENTS[src_ip]
            return seg
        return "NORMAL_HOST"

    def _update_detection_state(self, session_id, src_ip, packet_rate, mitigation_active):
        # UPDATED: parameter svm_prediction dihapus. Klasifikasi sekarang murni
        # berbasis rate (lihat _classify_rate), tidak ada lagi jalur konfirmasi
        # via model — begitu rate >= attack_rate_threshold, status langsung
        # ATTACK_CONFIRMED tanpa perlu menunggu confirmation_seconds.
        now = time.time()
        state = self.session_detection_state[session_id]
        old_status = state["status"]
        state["last_event_time"] = now

        if mitigation_active:
            state["status"] = "DROP_ACTIVE"
            return state

        warning_condition = packet_rate >= self.warning_rate_threshold
        if warning_condition and state["warning_since"] is None:
            state["warning_since"] = now

        alert_condition = packet_rate >= self.attack_rate_threshold

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

        return state

    def _should_activate_mitigation(self, session_id):
        if self.disable_mitigation:
            return False

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
            actions=[],
            idle_timeout=self.MITIGATION_IDLE_TIMEOUT,
            hard_timeout=self.MITIGATION_HARD_TIMEOUT,
        )

        attacker_mac = self._lookup_attacker_mac(src_ip)
        if attacker_mac is None:
            return

        arp_match = parser.OFPMatch(
            eth_type=0x0806,
            eth_src=attacker_mac,
            arp_spa=src_ip,
            arp_tpa=self.VICTIM_IP,
        )
        self.add_flow(
            datapath=datapath,
            priority=200,
            match=arp_match,
            actions=[],
            idle_timeout=self.MITIGATION_IDLE_TIMEOUT,
            hard_timeout=self.MITIGATION_HARD_TIMEOUT,
        )

    def _resolve_mitigation_datapath(self, src_ip, fallback_datapath):
        if src_ip in self.ATTACKER_SEGMENTS:
            target_dpid, _ = self.ATTACKER_SEGMENTS[src_ip]
            target_dp = self.datapaths.get(target_dpid)
            if target_dp is not None:
                return target_dp, target_dpid
        return fallback_datapath, fallback_datapath.id

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
                        self.MITIGATION_IDLE_TIMEOUT, self.MITIGATION_HARD_TIMEOUT,
                        f"DROP rule installed — ICMP + ARP from {src_ip} blocked at switch level",
                    ])

                    self._log_mitigation_event(
                        "DROP_INSTALLED", src_ip, hostname, self.VICTIM_IP,
                        switch_name=self.SWITCH_DPID_MAP.get(target_dpid, "unknown"),
                        hard_timeout=self.MITIGATION_HARD_TIMEOUT,
                    )

                elif action == "DELETE":
                    self._append_csv(self.mitigation_log_path, [
                        now_str, src_ip, hostname,
                        target_dpid if target_dpid else "",
                        self.SWITCH_DPID_MAP.get(target_dpid, "unknown") if target_dpid else "",
                        seg_desc,
                        "RELEASE_DROP",
                        "HARD_TIMEOUT_EXPIRED",
                        self.MITIGATION_IDLE_TIMEOUT, self.MITIGATION_HARD_TIMEOUT,
                        "DROP rule expired — network returned to NORMAL phase",
                    ])
                    # NOTE: log "DROP_EXPIRED" sudah dicetak sekali di
                    # _refresh_mitigation_state() saat expired terdeteksi —
                    # tidak dicetak lagi di sini supaya tidak duplikat.

            except Exception as e:
                self.logger.error("Mitigation worker error: %s", e)

    def _apply_mitigation_if_needed(self, datapath, src_ip):
        if self.disable_mitigation:
            return "OFF"

        target_dp, target_dpid = self._resolve_mitigation_datapath(src_ip, datapath)
        state = self.active_mitigations[src_ip]

        if state["active"]:
            return "DROP_ACTIVE"

        now_str  = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        _, seg   = self.ATTACKER_SEGMENTS.get(src_ip, (target_dpid, "UNKNOWN_SEGMENT"))
        hostname = self.ATTACKER_IPS.get(src_ip, "UNKNOWN")

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
        state = self.active_mitigations[src_ip]

        if not state["active"] or state["start_time"] is None:
            return "OFF"

        elapsed = time.time() - state["start_time"]

        if elapsed >= self.MITIGATION_HARD_TIMEOUT:
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

            self.last_alert_log_time[src_ip]   = 0.0
            self.last_warning_log_time[src_ip]  = 0.0

            session_id = f"{src_ip}->{self.VICTIM_IP}:ICMP"
            ds = self.session_detection_state[session_id]
            ds.update({
                "status":          "NORMAL",
                "warning_since":   None,
                "confirmed_since": None,
                "alert_first_seen": None,
            })
            self._log_mitigation_event(
                "DROP_EXPIRED", src_ip, hostname, self.VICTIM_IP, phase="NORMAL",
            )

            return "OFF"

        return "DROP_ACTIVE"

    def _cleanup_stale_sessions(self):
        now   = time.time()
        stale = [sid for sid, q in self.session_packet_times.items()
                 if not q or (now - q[-1]) > self._session_max_age]
        for sid in stale:
            self.session_packet_times.pop(sid, None)
            self.session_packet_sizes.pop(sid, None)
            self.session_stats.pop(sid, None)
            self.session_detection_state.pop(sid, None)
        if stale:
            self.logger.debug("Session cleanup: %d stale sessions removed", len(stale))

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

        # PATCH (a): hard_timeout diganti dari 60 -> FORWARDING_HARD_TIMEOUT (0).
        # Sebelumnya flow forwarding non-ICMP selalu expired paksa di 60 detik
        # walau traffic masih aktif mengalir, sehingga transfer panjang
        # (mis. nc 100KB, curl berkali-kali) bisa terputus di tengah jalan.
        # idle_timeout tetap dipertahankan supaya flow yang benar-benar sudah
        # tidak dipakai (tidak ada traffic sama sekali) tetap dibersihkan.
        if out_port != ofproto.OFPP_FLOOD and icmp_pkt is None:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions,
                            buffer_id=msg.buffer_id,
                            idle_timeout=self.FORWARDING_IDLE_TIMEOUT,
                            hard_timeout=self.FORWARDING_HARD_TIMEOUT)
            else:
                self.add_flow(datapath, 10, match, actions,
                            idle_timeout=self.FORWARDING_IDLE_TIMEOUT,
                            hard_timeout=self.FORWARDING_HARD_TIMEOUT)

        if arp_pkt is not None:
            # PATCH (b): pasang flow permanen (idle_timeout panjang,
            # hard_timeout=0) khusus untuk ARP per pasangan MAC, supaya ARP
            # tidak selalu nyangkut ke controller berulang-ulang. Sebelumnya
            # SEMUA paket ARP di-packet_out lewat controller tanpa pernah
            # dipasang flow sama sekali, sehingga ARP mendominasi jumlah
            # paket di traffic capture secara terus-menerus, bukan cuma
            # sekali di awal seperti pada jaringan normal yang meng-cache ARP.
            if out_port != ofproto.OFPP_FLOOD:
                arp_learn_match = parser.OFPMatch(
                    in_port=in_port, eth_type=0x0806,
                    eth_src=src_mac, eth_dst=dst_mac,
                )
                self.add_flow(datapath, 15, arp_learn_match, actions,
                            idle_timeout=self.ARP_FLOW_IDLE_TIMEOUT,
                            hard_timeout=self.ARP_FLOW_HARD_TIMEOUT)
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        if icmp_pkt is None:
            if ip_pkt is not None:
                src_ip   = ip_pkt.src
                dst_ip   = ip_pkt.dst
                proto    = self._get_protocol_name(eth.ethertype, ip_pkt.proto)
                sp, dp   = self._get_tcp_udp_ports(pkt)
                if proto in ["TCP", "UDP"]:
                    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                    packet_size = len(msg.data) if msg.data is not None else 0
                    session_id = self._get_session_id(src_ip, dst_ip, proto, sp, dp)

                    packet_features = self._get_session_window_features(session_id, packet_size)
                    packet_rate = packet_features["packet_rate"]
                    session = self._update_session_stats(session_id, timestamp)
                    packet_count = session["packet_count"]

                    any_mitigation = any(v["active"] for v in self.active_mitigations.values())
                    phase = "MITIGATED" if any_mitigation else "NORMAL"

                    event_note = "tcp_normal" if proto == "TCP" else "udp_normal"

                    # UPDATED: 12 kolom (final_prediction dihapus)
                    self._append_csv(self.traffic_analysis_path, [
                        timestamp, src_ip, dst_ip, proto, session_id,
                        "NORMAL", phase,
                        round(packet_features["packet_rate"], 4), packet_count,
                        5, dpid_name,
                        event_note,
                    ])
                    key = f"{proto}:{src_ip}->{dst_ip}:{dp}"
                    if self._should_log_info(key):
                        self._log_traffic_status(
                            "NORMAL", src_ip, dst_ip, packet_rate, threat_score=5,
                            phase=phase, protocol=proto, src_port=sp, dst_port=dp,
                        )
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        if ip_pkt is None or icmp_pkt.type != 8:
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        packet_size = len(msg.data) if msg.data is not None else 0
        session_id = self._get_session_id(src_ip, dst_ip, "ICMP")
        packet_features = self._get_session_window_features(session_id, packet_size)
        packet_rate = packet_features["packet_rate"]
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        session     = self._update_session_stats(session_id, timestamp)
        packet_count = session["packet_count"]

        if dst_ip != self.VICTIM_IP:
            # Phase selalu NORMAL di sini karena mitigasi hanya pernah
            # menyasar traffic menuju VICTIM_IP; traffic ke host lain
            # tidak pernah dipengaruhi status mitigasi manapun.
            phase = "NORMAL"
            # UPDATED: 12 kolom
            self._append_csv(self.traffic_analysis_path, [
                timestamp, src_ip, dst_ip, "ICMP", session_id,
                "NORMAL", phase,
                round(packet_features["packet_rate"], 4), packet_count,
                5, dpid_name,
                "icmp_non_victim",
            ])
            key = f"ICMP:{src_ip}->{dst_ip}"
            if self._should_log_info(key):
                self._log_traffic_status(
                    "NORMAL", src_ip, dst_ip, packet_rate, threat_score=5, phase=phase,
                )
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        is_attacker = src_ip in self.ATTACKER_IPS

        mitigation_status = "OFF"
        if is_attacker:
            mitigation_status = self._refresh_mitigation_state(src_ip)
        mitigation_active = (mitigation_status == "DROP_ACTIVE")

        # If attacker is currently mitigated, swallow controller-side packets
        # to avoid per-packet logging and forwarding noise (switch handles drops).
        if is_attacker and mitigation_active:
            return

        if not is_attacker:
            any_mitigation = any(
                v["active"] for v in self.active_mitigations.values()
            )
            phase = "MITIGATED" if any_mitigation else "NORMAL"

            # UPDATED: 12 kolom
            self._append_csv(self.traffic_analysis_path, [
                timestamp, src_ip, dst_ip, "ICMP", session_id,
                "NORMAL", phase,
                round(packet_features["packet_rate"], 4), packet_count,
                5, dpid_name,
                "icmp_to_victim",
            ])
            key = f"BASELINE:{src_ip}->{dst_ip}"
            if self._should_log_info(key):
                self._log_traffic_status(
                    "NORMAL", src_ip, dst_ip, packet_rate, threat_score=5, phase=phase,
                )
            self._send_packet_out(datapath, msg, in_port, actions)
            return

        # UPDATED: klasifikasi murni dari raw rate (EWMA dihapus) via
        # _classify_rate — lihat catatan di __init__ dan
        # _get_session_window_features soal alasan penghapusan EWMA.
        final_prediction = self._classify_rate(packet_rate)

        detection_state = self._update_detection_state(
            session_id, src_ip, packet_rate, mitigation_active)
        detection_status = detection_state["status"]

        # rate_to_log: satu-satunya angka rate yang dipakai dari titik ini
        # sampai ke CSV maupun console — sama persis dengan packet_rate yang
        # memicu keputusan di _classify_rate/_update_detection_state di atas.
        # Di-nol-kan hanya saat mitigation_active (attacker sedang di-drop,
        # tidak ada paket baru yang benar-benar diukur).
        rate_to_log = 0.0 if mitigation_active else packet_rate

        if mitigation_active:
            final_prediction_log = 0
            event_note = "attacker_blocked"
            phase      = "MITIGATED"
        elif detection_status == "ATTACK_CONFIRMED":
            final_prediction_log = final_prediction
            event_note = "flood_confirmed"
            phase      = "ATTACK"
        elif detection_status == "WARNING":
            final_prediction_log = final_prediction
            event_note = "rate_warning"
            phase      = "ATTACK"
        else:
            final_prediction_log = final_prediction
            event_note = "icmp_normal"
            phase      = "NORMAL"

        threat_score = self._calculate_threat_score(rate_to_log, final_prediction_log)

        should_write_csv = True
        if mitigation_active:
            key_csv = f"csv_drop:{src_ip}"
            if not self._should_log_info(key_csv):
                should_write_csv = False

        if should_write_csv:
            # UPDATED: 12 kolom (final_prediction_log dihapus dari row)
            self._append_csv(self.traffic_analysis_path, [
                timestamp, src_ip, dst_ip, "ICMP", session_id,
                detection_status, phase,
                round(rate_to_log, 4), packet_count,
                threat_score, dpid_name,
                event_note,
            ])

        # NOTE: cabang "mitigation_active" DIHAPUS di sini — sudah dijamin
        # dead code karena paket attacker yang sedang di-drop sudah
        # di-swallow duluan oleh `if is_attacker and mitigation_active: return`
        # di atas. Event mitigasi (DROP_INSTALLED/DROP_EXPIRED) dicetak
        # terpisah lewat _log_mitigation_event(), bukan di sini — lihat
        # penjelasan di definisi _log_traffic_status/_log_mitigation_event.

        if detection_status == "ATTACK_CONFIRMED":
            if self._should_log_alert(src_ip):
                self._log_traffic_status(
                    "ATTACK", src_ip, dst_ip, rate_to_log, threat_score, phase,
                )

            if self._should_activate_mitigation(session_id):
                self._apply_mitigation_if_needed(datapath, src_ip)

        elif detection_status == "WARNING":
            if self._should_log_warning(src_ip):
                self._log_traffic_status(
                    "WARNING", src_ip, dst_ip, rate_to_log, threat_score, phase,
                )

        else:
            if self._should_log_info(f"ICMP:{src_ip}->{dst_ip}"):
                self._log_traffic_status(
                    "NORMAL", src_ip, dst_ip, rate_to_log, threat_score, phase,
                )

        self._send_packet_out(datapath, msg, in_port, actions)