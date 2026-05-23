#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN ICMP Flood — Feature Collector for SVM Training (v2)
Capture SEMUA ICMP echo request, per-flow (src,dst) aggregation.

ENV: FEATURE_LABEL=normal|attack|unlabeled
Run: FEATURE_LABEL=normal ryu-manager /home/kali/sdn-icmp/training/feature_collector.py
"""

import os
import csv
import time
import statistics
from collections import defaultdict, deque
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub


class FeatureCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    BASE_DIR    = "/home/kali/sdn-icmp"
    OUTPUT_DIR  = os.path.join(BASE_DIR, "data", "raw")

    VICTIM_IP         = "10.0.0.25"
    WINDOW_SECONDS    = 1.0
    EWMA_ALPHA        = 0.3
    ICMP_ECHO_REQUEST = 8

    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RED    = "\033[91m"
    RESET  = "\033[0m"

    def __init__(self, *args, **kwargs):
        super(FeatureCollector, self).__init__(*args, **kwargs)

        self.label_hint = os.environ.get("FEATURE_LABEL", "unlabeled").lower().strip()
        if self.label_hint not in ("normal", "attack", "unlabeled"):
            self.logger.warning(
                "%s[FC] FEATURE_LABEL=%r tidak dikenal, pakai 'unlabeled'%s",
                self.YELLOW, self.label_hint, self.RESET
            )
            self.label_hint = "unlabeled"

        self.output_path = os.path.join(
            self.OUTPUT_DIR,
            "feature_dataset_{}.csv".format(self.label_hint)
        )

        self.window_buffer = defaultdict(deque)
        self.ewma_rate     = defaultdict(float)
        self.window_count  = defaultdict(int)
        self.mac_to_port   = defaultdict(dict)

        self._init_csv()

        self._stop_flag = False
        self._flush_thread = hub.spawn(self._window_flusher)

        self._banner()

    def _init_csv(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        is_new = (not os.path.exists(self.output_path)) or \
                 (os.path.getsize(self.output_path) == 0)
        if is_new:
            header = [
                "timestamp_window_end",
                "src_ip",
                "dst_ip",
                "is_to_victim",
                "packet_rate_ewma",
                "packet_count_1s",
                "byte_count_1s",
                "avg_pkt_size",
                "pkt_size_std",
                "inter_arrival_std",
                "label_hint",
            ]
            with open(self.output_path, "w", newline="") as f:
                csv.writer(f).writerow(header)
            self.logger.info("%s[FC] CSV baru dibuat: %s%s",
                             self.GREEN, self.output_path, self.RESET)
        else:
            self.logger.info("%s[FC] CSV sudah ada, append ke: %s%s",
                             self.YELLOW, self.output_path, self.RESET)

    def _append_row(self, row):
        with open(self.output_path, "a", newline="") as f:
            csv.writer(f).writerow(row)

    def _banner(self):
        self.logger.info("%s%s%s", self.CYAN, "=" * 75, self.RESET)
        self.logger.info("%s[FC] SDN ICMP Feature Collector v2%s",
                         self.CYAN, self.RESET)
        color = self.GREEN if self.label_hint == "normal" else (
            self.RED if self.label_hint == "attack" else self.YELLOW)
        self.logger.info("%s[FC] Label   : %s%s%s",
                         self.CYAN, color, self.label_hint.upper(), self.RESET)
        self.logger.info("%s[FC] Window  : %.1f detik%s",
                         self.CYAN, self.WINDOW_SECONDS, self.RESET)
        self.logger.info("%s[FC] Output  : %s%s",
                         self.CYAN, self.output_path, self.RESET)
        self.logger.info("%s[FC] Scope   : ALL ICMP echo requests (per flow)%s",
                         self.CYAN, self.RESET)
        self.logger.info("%s[FC] Victim  : %s (flagged is_to_victim=1)%s",
                         self.CYAN, self.VICTIM_IP, self.RESET)
        self.logger.info("%s%s%s", self.CYAN, "=" * 75, self.RESET)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 100, match, actions)

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

        self.logger.info("%s[FC] Switch %d connected & ICMP mirror installed%s",
                         self.GREEN, datapath.id, self.RESET)

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority,
                      match=match, instructions=inst)
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:
            return

        dpid    = datapath.id
        src_mac = eth.src
        dst_mac = eth.dst

        self.mac_to_port[dpid][src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_src=src_mac, eth_dst=dst_mac)
            self._add_flow(datapath, 10, match, actions,
                           buffer_id=msg.buffer_id)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if ip_pkt is None or icmp_pkt is None:
            return
        if icmp_pkt.type != self.ICMP_ECHO_REQUEST:
            return

        src_ip   = ip_pkt.src
        dst_ip   = ip_pkt.dst
        flow_key = (src_ip, dst_ip)

        now      = time.time()
        pkt_size = len(msg.data)
        self.window_buffer[flow_key].append((now, pkt_size))

    def _window_flusher(self):
        seen_flows = set()
        while not self._stop_flag:
            hub.sleep(self.WINDOW_SECONDS)
            window_end = time.time()
            window_start = window_end - self.WINDOW_SECONDS

            current_flows = list(self.window_buffer.keys())
            for f in current_flows:
                seen_flows.add(f)

            for flow_key in seen_flows:
                src_ip, dst_ip = flow_key
                buf = self.window_buffer[flow_key]
                while buf and buf[0][0] < window_start:
                    buf.popleft()

                features = self._compute_features(flow_key, buf)
                if features["packet_count_1s"] == 0:
                    continue

                timestamp_str = datetime.fromtimestamp(window_end).strftime(
                    "%Y-%m-%d %H:%M:%S.%f")[:-3]
                is_to_victim = 1 if dst_ip == self.VICTIM_IP else 0

                self._append_row([
                    timestamp_str,
                    src_ip,
                    dst_ip,
                    is_to_victim,
                    round(features["packet_rate_ewma"], 4),
                    features["packet_count_1s"],
                    features["byte_count_1s"],
                    round(features["avg_pkt_size"], 2),
                    round(features["pkt_size_std"], 4),
                    round(features["inter_arrival_std"], 6),
                    self.label_hint,
                ])

                self.window_count[flow_key] += 1
                if self.window_count[flow_key] % 10 == 0:
                    victim_tag = " [VICTIM]" if is_to_victim else ""
                    self.logger.info(
                        "%s[FC] %s->%s%s | win=%d | rate=%.2f | "
                        "sstd=%.2f | iat=%.4f%s",
                        self.GREEN, src_ip, dst_ip, victim_tag,
                        self.window_count[flow_key],
                        features["packet_rate_ewma"],
                        features["pkt_size_std"],
                        features["inter_arrival_std"],
                        self.RESET)

    def _compute_features(self, flow_key, buf):
        if len(buf) == 0:
            return {
                "packet_rate_ewma":   0.0,
                "packet_count_1s":    0,
                "byte_count_1s":      0,
                "avg_pkt_size":       0.0,
                "pkt_size_std":       0.0,
                "inter_arrival_std":  0.0,
            }

        timestamps = [t for t, _ in buf]
        sizes      = [s for _, s in buf]

        raw_rate = float(len(buf)) / self.WINDOW_SECONDS
        prev_ewma = self.ewma_rate[flow_key]
        smoothed = self.EWMA_ALPHA * raw_rate + (1.0 - self.EWMA_ALPHA) * prev_ewma
        self.ewma_rate[flow_key] = smoothed

        packet_count = len(buf)
        byte_count   = sum(sizes)
        avg_size     = byte_count / packet_count

        if packet_count >= 2:
            pkt_size_std = statistics.stdev(sizes)
        else:
            pkt_size_std = 0.0

        if packet_count >= 3:
            inter_arrivals = [timestamps[i+1] - timestamps[i]
                              for i in range(len(timestamps) - 1)]
            inter_arrival_std = statistics.stdev(inter_arrivals)
        else:
            inter_arrival_std = 0.0

        return {
            "packet_rate_ewma":   smoothed,
            "packet_count_1s":    packet_count,
            "byte_count_1s":      byte_count,
            "avg_pkt_size":       avg_size,
            "pkt_size_std":       pkt_size_std,
            "inter_arrival_std":  inter_arrival_std,
        }
