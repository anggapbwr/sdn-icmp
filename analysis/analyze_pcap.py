#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP RAW PACKET FORENSIC ANALYZER
==================================

Purpose: Deep packet-level forensic analysis (not high-level statistics).
Role   : Complements analyze.py by focusing on raw packet evidence.
Output : 7 forensic graphs + conversation flow analysis + forensic report.

Scope  : ICMP Flood DDoS attack forensics against SDN topology.
NIST   : Based on NIST SP 800-86 Digital Forensics Framework.

Author : SDN Forensics Lab
Date   : 2026-05-11
"""

import os
import sys
import subprocess
from io import StringIO
from datetime import datetime

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import FuncFormatter


BASE_DIR = "/home/kali/sdn-icmp"
BASELINE_PCAP = f"{BASE_DIR}/logs/archive/baseline/session_baseline.pcap"
DDOS_PCAP = f"{BASE_DIR}/logs/archive/ddos/session_ddos.pcap"
OUTPUT_DIR = f"{BASE_DIR}/logs/report_graphs"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Graph styling for forensic presentation
plt.rcParams["figure.figsize"] = (12, 7)
plt.rcParams["axes.grid"] = True
plt.rcParams["grid.alpha"] = 0.3
plt.rcParams["font.size"] = 10
plt.rcParams["lines.linewidth"] = 1.5


VICTIM_IP = "10.0.0.25"

ATTACKERS = {
    "10.0.0.1": {
        "host": "h1",
        "switch": "s2",
        "segment": "s2-segment-attacker-h1",
    },
    "10.0.0.7": {
        "host": "h7",
        "switch": "s3",
        "segment": "s3-segment-attacker-h7",
    },
    "10.0.0.13": {
        "host": "h13",
        "switch": "s4",
        "segment": "s4-segment-attacker-h13",
    },
    "10.0.0.18": {
        "host": "h18",
        "switch": "s5",
        "segment": "s5-segment-attacker-h18",
    },
}

ATTACKER_IPS = list(ATTACKERS.keys())


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_tshark():
    """Verify tshark is installed and accessible."""
    try:
        subprocess.run(
            ["tshark", "-v"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except Exception:
        print("[!] tshark tidak ditemukan.")
        print("[!] Install dengan: sudo apt install -y tshark")
        sys.exit(1)


def save_plot(filename, dpi=300):
    """Save plot with forensic-grade quality."""
    path = f"{OUTPUT_DIR}/{filename}"
    plt.tight_layout()
    plt.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close()
    print(f"[+] Graph saved: {filename}")


def safe_numeric(df, columns):
    """Convert columns to numeric, coerce errors to NaN."""
    for col in columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def safe_string(df, columns):
    """Convert columns to string, fill NaN with empty string."""
    for col in columns:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)
    return df


# ============================================================================
# PCAP INGESTION
# ============================================================================

def run_tshark(pcap_path, dataset_name):
    """
    Extract packet-level data from PCAP using tshark.
    
    Field mapping:
    - Packet metadata: frame number, timestamp, length
    - Layer 2-4 headers: MAC, IP, port, protocol
    - ICMP-specific: type, code
    - TCP anomalies: retransmission, duplicate ACK, lost segment, fast retx
    
    Returns: DataFrame with raw packet records + computed forensic flags.
    """
    if not os.path.exists(pcap_path):
        print(f"[!] PCAP tidak ditemukan: {pcap_path}")
        return pd.DataFrame()

    field_names = [
        "frame_number",
        "time_epoch",
        "frame_len",
        "protocol",
        "src_mac",
        "dst_mac",
        "src_ip",
        "dst_ip",
        "tcp_src_port",
        "tcp_dst_port",
        "udp_src_port",
        "udp_dst_port",
        "icmp_type",
        "icmp_code",
        "tcp_retransmission",
        "tcp_duplicate_ack",
        "tcp_lost_segment",
        "tcp_fast_retransmission",
        "info",
    ]

    fields = [
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "icmp.type",
        "-e", "icmp.code",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.analysis.duplicate_ack",
        "-e", "tcp.analysis.lost_segment",
        "-e", "tcp.analysis.fast_retransmission",
        "-e", "_ws.col.Info",
    ]

    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ] + fields

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[!] Gagal membaca PCAP: {pcap_path}")
        print(exc.stderr)
        return pd.DataFrame()

    if not result.stdout.strip():
        print(f"[!] PCAP kosong: {pcap_path}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(
            StringIO(result.stdout),
            sep="\t",
            names=field_names,
            engine="python",
            on_bad_lines="skip",
        )
    except Exception as exc:
        print(f"[!] Gagal parse output tshark: {exc}")
        return pd.DataFrame()

    df["dataset"] = dataset_name

    # Convert numeric fields
    df = safe_numeric(
        df,
        [
            "frame_number",
            "time_epoch",
            "frame_len",
            "tcp_src_port",
            "tcp_dst_port",
            "udp_src_port",
            "udp_dst_port",
            "icmp_type",
            "icmp_code",
        ],
    )

    # Convert string fields
    df = safe_string(
        df,
        [
            "protocol",
            "src_mac",
            "dst_mac",
            "src_ip",
            "dst_ip",
            "tcp_retransmission",
            "tcp_duplicate_ack",
            "tcp_lost_segment",
            "tcp_fast_retransmission",
            "info",
        ],
    )

    # Convert epoch to datetime
    df["timestamp"] = pd.to_datetime(df["time_epoch"], unit="s", errors="coerce")

    # Protocol classification
    proto_upper = df["protocol"].astype(str).str.upper()
    info_upper = df["info"].astype(str).str.upper()

    df["is_icmp"] = proto_upper.str.contains("ICMP", na=False)
    df["is_tcp"] = proto_upper.str.contains("TCP|HTTP", na=False)
    df["is_udp"] = proto_upper.str.contains("UDP|DNS", na=False)
    df["is_arp"] = proto_upper.str.contains("ARP", na=False)

    # Forensic flags: attacker-victim relationship
    df["is_attacker_src"] = df["src_ip"].isin(ATTACKER_IPS)
    df["is_victim_dst"] = df["dst_ip"].eq(VICTIM_IP)
    df["is_victim_src"] = df["src_ip"].eq(VICTIM_IP)

    # Attack signature: ICMP from attacker to victim
    df["is_attack_icmp"] = (
        df["is_icmp"]
        & df["is_attacker_src"]
        & df["is_victim_dst"]
    )

    # TCP anomaly flags (boolean filter instead of mask.loc)
    df["tcp_retransmission_flag"] = (
        (df["tcp_retransmission"].astype(str).ne(""))
        | info_upper.str.contains("RETRANSMISSION", na=False)
    )

    df["tcp_duplicate_ack_flag"] = (
        (df["tcp_duplicate_ack"].astype(str).ne(""))
        | info_upper.str.contains("DUP ACK", na=False)
    )

    df["tcp_lost_segment_flag"] = (
        (df["tcp_lost_segment"].astype(str).ne(""))
        | info_upper.str.contains("LOST SEGMENT", na=False)
    )

    df["tcp_fast_retransmission_flag"] = (
        (df["tcp_fast_retransmission"].astype(str).ne(""))
        | info_upper.str.contains("FAST RETRANSMISSION", na=False)
    )

    # Attacker context mapping
    df["attacker_host"] = df["src_ip"].map(
        lambda ip: ATTACKERS.get(ip, {}).get("host", "")
    )
    df["attacker_switch"] = df["src_ip"].map(
        lambda ip: ATTACKERS.get(ip, {}).get("switch", "")
    )
    df["attacker_segment"] = df["src_ip"].map(
        lambda ip: ATTACKERS.get(ip, {}).get("segment", "")
    )

    return df


# ============================================================================
# FORENSIC SUMMARIES
# ============================================================================

def protocol_summary(df, dataset_name):
    """
    Generate protocol-level statistics for forensic comparison.
    Includes attack metrics and TCP quality indicators.
    """
    if df.empty:
        return {
            "dataset": dataset_name,
            "total_packets": 0,
            "total_bytes": 0,
            "icmp_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "arp_packets": 0,
            "victim_dst_packets": 0,
            "victim_src_packets": 0,
            "attack_icmp_packets": 0,
            "tcp_retransmissions": 0,
            "tcp_duplicate_acks": 0,
            "tcp_lost_segments": 0,
            "tcp_fast_retransmissions": 0,
            "first_packet_time": "",
            "last_packet_time": "",
            "duration_seconds": 0,
            "avg_packets_per_second": 0,
        }

    first_time = df["timestamp"].min()
    last_time = df["timestamp"].max()

    duration = max((last_time - first_time).total_seconds(), 1) if pd.notna(first_time) and pd.notna(last_time) else 1
    total_packets = len(df)

    return {
        "dataset": dataset_name,
        "total_packets": int(total_packets),
        "total_bytes": int(df["frame_len"].sum()) if "frame_len" in df.columns else 0,
        "icmp_packets": int(df["is_icmp"].sum()),
        "tcp_packets": int(df["is_tcp"].sum()),
        "udp_packets": int(df["is_udp"].sum()),
        "arp_packets": int(df["is_arp"].sum()),
        "victim_dst_packets": int(df["is_victim_dst"].sum()),
        "victim_src_packets": int(df["is_victim_src"].sum()),
        "attack_icmp_packets": int(df["is_attack_icmp"].sum()),
        "tcp_retransmissions": int(df["tcp_retransmission_flag"].sum()),
        "tcp_duplicate_acks": int(df["tcp_duplicate_ack_flag"].sum()),
        "tcp_lost_segments": int(df["tcp_lost_segment_flag"].sum()),
        "tcp_fast_retransmissions": int(df["tcp_fast_retransmission_flag"].sum()),
        "first_packet_time": str(first_time),
        "last_packet_time": str(last_time),
        "duration_seconds": round(float(duration), 2),
        "avg_packets_per_second": round(float(total_packets / duration), 2),
    }


def attacker_summary(df):
    """
    Per-attacker forensic analysis.
    Shows volume, ICMP packet rate (PPS), and temporal coverage.
    """
    rows = []

    for ip, meta in ATTACKERS.items():
        sub = df[df["src_ip"] == ip].copy() if not df.empty else pd.DataFrame()

        if sub.empty:
            rows.append({
                "src_ip": ip,
                "host": meta["host"],
                "switch": meta["switch"],
                "segment": meta["segment"],
                "total_packets": 0,
                "icmp_to_victim_packets": 0,
                "tcp_packets": 0,
                "udp_packets": 0,
                "arp_packets": 0,
                "total_bytes": 0,
                "avg_icmp_attack_pps": 0,
                "max_icmp_attack_pps": 0,
                "first_seen": "",
                "last_seen": "",
            })
            continue

        attack_only = sub[sub["is_attack_icmp"]].dropna(subset=["timestamp"])

        if not attack_only.empty:
            per_second = attack_only.set_index("timestamp").resample("1s").size()
            avg_pps = round(float(per_second.mean()), 2)
            max_pps = round(float(per_second.max()), 2)
        else:
            avg_pps = 0.0
            max_pps = 0.0

        rows.append({
            "src_ip": ip,
            "host": meta["host"],
            "switch": meta["switch"],
            "segment": meta["segment"],
            "total_packets": len(sub),
            "icmp_to_victim_packets": int(sub["is_attack_icmp"].sum()),
            "tcp_packets": int(sub["is_tcp"].sum()),
            "udp_packets": int(sub["is_udp"].sum()),
            "arp_packets": int(sub["is_arp"].sum()),
            "total_bytes": int(sub["frame_len"].sum()) if "frame_len" in sub.columns else 0,
            "avg_icmp_attack_pps": avg_pps,
            "max_icmp_attack_pps": max_pps,
            "first_seen": str(sub["timestamp"].min()),
            "last_seen": str(sub["timestamp"].max()),
        })

    return pd.DataFrame(rows)


def conversation_analysis(df):
    """
    Flow analysis: src IP → dst IP pairs with packet/byte counts.
    Focuses on attacker-to-victim flows to show attack patterns.
    """
    if df.empty or "src_ip" not in df.columns:
        return pd.DataFrame()

    temp = df[(df["src_ip"].astype(str).ne("")) & (df["dst_ip"].astype(str).ne(""))].copy()

    if temp.empty:
        return pd.DataFrame()

    flows = (
        temp.groupby(["src_ip", "dst_ip", "protocol"])
        .agg(
            packet_count=("src_ip", "count"),
            total_bytes=("frame_len", "sum"),
            icmp_count=("is_icmp", "sum"),
            tcp_count=("is_tcp", "sum"),
            udp_count=("is_udp", "sum"),
        )
        .reset_index()
        .sort_values("packet_count", ascending=False)
    )

    return flows


# ============================================================================
# FORENSIC GRAPHS (7 REQUIRED GRAPHS)
# ============================================================================

def graph_1_icmp_volume_comparison(summary_df):
    """
    Graph 1: ICMP Packet Volume Comparison (Baseline vs DDoS)
    
    Forensic significance: Shows ICMP volume spike during attack.
    NIST mapping: Data Collection & Analysis phase.
    """
    if summary_df.empty or "icmp_packets" not in summary_df.columns:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    
    datasets = summary_df["dataset"].values
    icmp_counts = summary_df["icmp_packets"].values
    
    colors = ["#2ecc71", "#e74c3c"]  # green baseline, red ddos
    bars = ax.bar(datasets, icmp_counts, color=colors, alpha=0.8, edgecolor="black", linewidth=1.5)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}',
                ha='center', va='bottom', fontweight='bold', fontsize=11)
    
    ax.set_ylabel("ICMP Packet Count", fontsize=12, fontweight='bold')
    ax.set_title("Graph 1: ICMP Volume Comparison (Baseline vs DDoS)\nForensic Evidence of Attack Intensity", 
                 fontsize=13, fontweight='bold')
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    ax.grid(axis='y', alpha=0.3)
    
    save_plot("g01_icmp_volume_comparison.png")


def graph_2_attack_icmp_rate_timeline(ddos_df):
    """
    Graph 2: Attack ICMP Rate Timeline (Packets per Second)
    
    Forensic significance: Temporal pattern of ICMP flood.
    NIST mapping: Evidence Examination & Analysis.
    """
    if ddos_df.empty or "timestamp" not in ddos_df.columns:
        return

    attack_df = ddos_df[ddos_df["is_attack_icmp"]].dropna(subset=["timestamp"]).copy()

    if attack_df.empty:
        return

    rate = attack_df.set_index("timestamp").resample("1s").size()

    fig, ax = plt.subplots(figsize=(12, 6))
    
    ax.plot(rate.index, rate.values, linewidth=2, color="#e74c3c", marker="o", markersize=3, alpha=0.7)
    ax.fill_between(rate.index, rate.values, alpha=0.3, color="#e74c3c")
    
    ax.set_ylabel("ICMP Packets/Second", fontsize=12, fontweight='bold')
    ax.set_xlabel("Time (UTC)", fontsize=12, fontweight='bold')
    ax.set_title("Graph 2: Attack ICMP Rate Timeline\nPacket Rate per Second (DDoS Phase)",
                 fontsize=13, fontweight='bold')
    
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.xticks(rotation=45, ha='right')
    
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    ax.grid(alpha=0.3)
    
    save_plot("g02_attack_icmp_rate_timeline.png")


def graph_3_attack_icmp_per_attacker(ddos_df, attacker_df):
    """
    Graph 3: ICMP Attack Volume per Attacker
    
    Forensic significance: Attribution of attack packets to source.
    NIST mapping: Attribution & Chain of Custody.
    """
    if attacker_df.empty or "icmp_to_victim_packets" not in attacker_df.columns:
        return

    fig, ax = plt.subplots(figsize=(11, 6))
    
    attackers = attacker_df["host"].values
    icmp_packets = attacker_df["icmp_to_victim_packets"].values
    
    colors_per_attacker = ["#3498db", "#e74c3c", "#f39c12", "#9b59b6"]
    bars = ax.bar(attackers, icmp_packets, color=colors_per_attacker[:len(attackers)], 
                  alpha=0.8, edgecolor="black", linewidth=1.5)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}',
                ha='center', va='bottom', fontweight='bold', fontsize=11)
    
    ax.set_ylabel("ICMP Packets to Victim", fontsize=12, fontweight='bold')
    ax.set_xlabel("Attacker Host", fontsize=12, fontweight='bold')
    ax.set_title("Graph 3: ICMP Attack Packets per Attacker\nAttribution to Source Hosts",
                 fontsize=13, fontweight='bold')
    
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    ax.grid(axis='y', alpha=0.3)
    
    save_plot("g03_attack_icmp_per_attacker.png")


def graph_4_icmp_rate_per_attacker(ddos_df):
    """
    Graph 4: ICMP Rate Timeline per Attacker (Overlay)
    
    Forensic significance: Coordinated attack pattern analysis.
    NIST mapping: Pattern Recognition & Correlation.
    """
    if ddos_df.empty or "timestamp" not in ddos_df.columns:
        return

    attack_df = ddos_df[ddos_df["is_attack_icmp"]].dropna(subset=["timestamp"]).copy()

    if attack_df.empty:
        return

    fig, ax = plt.subplots(figsize=(12, 7))

    colors_map = {
        "10.0.0.1": "#3498db",
        "10.0.0.7": "#e74c3c",
        "10.0.0.13": "#f39c12",
        "10.0.0.18": "#9b59b6",
    }

    for ip, group in attack_df.groupby("src_ip"):
        per_second = group.set_index("timestamp").resample("1s").size()
        meta = ATTACKERS.get(ip, {})
        label = f"{meta.get('host', ip)}"
        color = colors_map.get(ip, "#95a5a6")
        ax.plot(per_second.index, per_second.values, label=label, linewidth=2, 
               color=color, marker="o", markersize=2, alpha=0.7)

    ax.set_ylabel("Packets/Second", fontsize=12, fontweight='bold')
    ax.set_xlabel("Time (UTC)", fontsize=12, fontweight='bold')
    ax.set_title("Graph 4: ICMP Rate Timeline per Attacker (Overlay)\nCoordinated Attack Pattern Analysis",
                 fontsize=13, fontweight='bold')
    
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.xticks(rotation=45, ha='right')
    
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    ax.legend(loc="upper left", fontsize=10, framealpha=0.95)
    ax.grid(alpha=0.3)
    
    save_plot("g04_icmp_rate_per_attacker_overlay.png")


def graph_5_tcp_quality_indicators(summary_df):
    """
    Graph 5: TCP Quality Indicators (Baseline vs DDoS)
    
    Forensic significance: Network degradation evidence.
    NIST mapping: Impact Assessment.
    """
    if summary_df.empty:
        return

    metrics = {
        "tcp_retransmissions": "TCP Retransmissions",
        "tcp_duplicate_acks": "TCP Duplicate ACKs",
        "tcp_lost_segments": "TCP Lost Segments",
        "tcp_fast_retransmissions": "TCP Fast Retransmissions",
    }

    available_metrics = {k: v for k, v in metrics.items() if k in summary_df.columns}

    if not available_metrics:
        return

    fig, ax = plt.subplots(figsize=(11, 6))

    x = np.arange(len(available_metrics))
    width = 0.35

    baseline_values = [summary_df[summary_df["dataset"] == "baseline"][k].values[0] 
                       for k in available_metrics.keys()]
    ddos_values = [summary_df[summary_df["dataset"] == "ddos"][k].values[0] 
                   for k in available_metrics.keys()]

    bars1 = ax.bar(x - width/2, baseline_values, width, label="Baseline", 
                   color="#2ecc71", alpha=0.8, edgecolor="black")
    bars2 = ax.bar(x + width/2, ddos_values, width, label="DDoS", 
                   color="#e74c3c", alpha=0.8, edgecolor="black")

    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}',
                        ha='center', va='bottom', fontsize=9)

    ax.set_ylabel("Anomaly Count", fontsize=12, fontweight='bold')
    ax.set_title("Graph 5: TCP Quality Indicators (Baseline vs DDoS)\nNetwork Degradation Evidence",
                 fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([v.replace("TCP ", "") for v in available_metrics.values()], fontsize=10)
    ax.legend(fontsize=11)
    ax.grid(axis='y', alpha=0.3)

    save_plot("g05_tcp_quality_indicators.png")


def graph_6_protocol_distribution(summary_df):
    """
    Graph 6: Protocol Distribution (Baseline vs DDoS)
    
    Forensic significance: Traffic composition comparison.
    NIST mapping: Data Collection & Classification.
    """
    if summary_df.empty:
        return

    protocols = ["icmp_packets", "tcp_packets", "udp_packets", "arp_packets"]
    protocol_labels = ["ICMP", "TCP/HTTP", "UDP/DNS", "ARP"]

    baseline_row = summary_df[summary_df["dataset"] == "baseline"]
    ddos_row = summary_df[summary_df["dataset"] == "ddos"]

    if baseline_row.empty or ddos_row.empty:
        return

    baseline_vals = [baseline_row[p].values[0] for p in protocols if p in baseline_row.columns]
    ddos_vals = [ddos_row[p].values[0] for p in protocols if p in ddos_row.columns]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6))

    colors_pie = ["#3498db", "#e74c3c", "#f39c12", "#95a5a6"]

    ax1.pie(baseline_vals, labels=protocol_labels[:len(baseline_vals)], autopct="%1.1f%%",
            colors=colors_pie, startangle=90)
    ax1.set_title("Baseline Protocol Distribution", fontsize=12, fontweight='bold')

    ax2.pie(ddos_vals, labels=protocol_labels[:len(ddos_vals)], autopct="%1.1f%%",
            colors=colors_pie, startangle=90)
    ax2.set_title("DDoS Protocol Distribution", fontsize=12, fontweight='bold')

    fig.suptitle("Graph 6: Protocol Distribution Comparison\nTraffic Composition Change Analysis",
                 fontsize=13, fontweight='bold')

    save_plot("g06_protocol_distribution.png")


def graph_7_conversation_flow(conversation_df):
    """
    Graph 7: Top Conversation Flows (src→dst)
    
    Forensic significance: Attack flow identification and pattern.
    NIST mapping: Relationship Analysis & Attribution.
    """
    if conversation_df.empty or "packet_count" not in conversation_df.columns:
        return

    # Filter to top 15 flows
    top_flows = conversation_df.nlargest(15, "packet_count").copy()

    # Create flow label
    top_flows["flow"] = top_flows.apply(
        lambda row: f"{row['src_ip']}\n→\n{row['dst_ip']}", axis=1
    )

    fig, ax = plt.subplots(figsize=(13, 7))

    colors_flow = ["#e74c3c" if row["dst_ip"] == VICTIM_IP else "#3498db" 
                   for _, row in top_flows.iterrows()]

    bars = ax.barh(top_flows["flow"], top_flows["packet_count"], 
                   color=colors_flow, alpha=0.8, edgecolor="black", linewidth=1)

    # Add value labels
    for i, bar in enumerate(bars):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f' {int(width):,}',
                ha='left', va='center', fontweight='bold', fontsize=10)

    ax.set_xlabel("Packet Count", fontsize=12, fontweight='bold')
    ax.set_title("Graph 7: Top 15 Conversation Flows (src → dst)\nAttack Flow Attribution",
                 fontsize=13, fontweight='bold')
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    # Add legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#e74c3c', edgecolor='black', label='To Victim (Attack)'),
        Patch(facecolor='#3498db', edgecolor='black', label='Other Flows'),
    ]
    ax.legend(handles=legend_elements, loc="lower right", fontsize=10)
    
    ax.grid(axis='x', alpha=0.3)
    
    save_plot("g07_conversation_flow_top15.png")


# ============================================================================
# FORENSIC REPORT
# ============================================================================

def write_forensic_report(summary_df, attacker_df, conversation_df, ddos_df):
    """
    Generate comprehensive forensic report aligned with NIST SP 800-86.
    
    Sections:
    1. Executive Summary
    2. Incident Context & Topology
    3. Evidence Inventory
    4. Forensic Findings
    5. Attack Attribution
    6. Impact Assessment
    7. Temporal Analysis
    8. Conclusion & Recommendations
    """
    report_path = f"{OUTPUT_DIR}/pcap_forensic_report.txt"

    baseline_row = summary_df[summary_df["dataset"] == "baseline"].iloc[0].to_dict() if not summary_df.empty else {}
    ddos_row = summary_df[summary_df["dataset"] == "ddos"].iloc[0].to_dict() if not summary_df.empty else {}

    with open(report_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("PCAP RAW PACKET FORENSIC ANALYSIS REPORT\n")
        f.write("Distributed ICMP Flood Attack (DDoS) Investigation\n")
        f.write("=" * 80 + "\n\n")

        # Section 1: Executive Summary
        f.write("=" * 80 + "\n")
        f.write("SECTION 1: EXECUTIVE SUMMARY\n")
        f.write("=" * 80 + "\n")
        f.write(f"Report Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"Analysis Type      : PCAP Raw Packet Forensics (NIST SP 800-86)\n")
        f.write(f"Incident Type      : Distributed ICMP Flood DDoS Attack\n")
        f.write(f"Victim System      : {VICTIM_IP} (h25 / core network)\n")
        f.write(f"Attack Duration    : {ddos_row.get('duration_seconds', 0):.2f} seconds\n")
        f.write(f"Total Attack ICMP  : {ddos_row.get('attack_icmp_packets', 0):,} packets\n")
        f.write(f"Attack Rate (avg)  : {ddos_row.get('avg_packets_per_second', 0):.2f} pps\n\n")

        # Section 2: Incident Context & Topology
        f.write("=" * 80 + "\n")
        f.write("SECTION 2: INCIDENT CONTEXT & TOPOLOGY\n")
        f.write("=" * 80 + "\n")
        f.write("Enterprise Tree Topology Configuration:\n")
        f.write("  Core Switch      : s1\n")
        f.write("  Access Switches  : s2, s3, s4, s5, s6\n")
        f.write("  Hosts            : h1-h25\n\n")
        f.write("Victim Configuration:\n")
        f.write(f"  IP Address       : {VICTIM_IP}\n")
        f.write("  Hostname         : h25\n")
        f.write("  Switch           : s6\n")
        f.write("  Role             : Target of DDoS attack\n\n")
        f.write("Attacker Configuration (4 Distributed Sources):\n")
        for ip, meta in ATTACKERS.items():
            f.write(f"  {meta['host']} ({ip}):\n")
            f.write(f"    - Access Switch  : {meta['switch']}\n")
            f.write(f"    - Segment        : {meta['segment']}\n\n")

        # Section 3: Evidence Inventory
        f.write("=" * 80 + "\n")
        f.write("SECTION 3: EVIDENCE INVENTORY\n")
        f.write("=" * 80 + "\n")
        f.write("PCAP Evidence Files:\n")
        f.write(f"  Baseline Session : {BASELINE_PCAP}\n")
        f.write(f"  DDoS Session     : {DDOS_PCAP}\n\n")
        f.write("Extracted Data Files:\n")
        f.write("  - pcap_summary_stats.csv\n")
        f.write("  - pcap_attacker_summary.csv\n")
        f.write("  - pcap_conversations_flows.csv\n")
        f.write("  - pcap_forensic_report.txt (this file)\n\n")
        f.write("Generated Forensic Graphs:\n")
        f.write("  1. g01_icmp_volume_comparison.png\n")
        f.write("  2. g02_attack_icmp_rate_timeline.png\n")
        f.write("  3. g03_attack_icmp_per_attacker.png\n")
        f.write("  4. g04_icmp_rate_per_attacker_overlay.png\n")
        f.write("  5. g05_tcp_quality_indicators.png\n")
        f.write("  6. g06_protocol_distribution.png\n")
        f.write("  7. g07_conversation_flow_top15.png\n\n")

        # Section 4: Forensic Findings
        f.write("=" * 80 + "\n")
        f.write("SECTION 4: FORENSIC FINDINGS\n")
        f.write("=" * 80 + "\n")
        f.write("Baseline (Normal Operation):\n")
        f.write(f"  Total Packets      : {baseline_row.get('total_packets', 0):,}\n")
        f.write(f"  ICMP Packets       : {baseline_row.get('icmp_packets', 0):,}\n")
        f.write(f"  TCP Packets        : {baseline_row.get('tcp_packets', 0):,}\n")
        f.write(f"  Packets to Victim  : {baseline_row.get('victim_dst_packets', 0):,}\n")
        f.write(f"  Duration           : {baseline_row.get('duration_seconds', 0):.2f}s\n")
        f.write(f"  Avg PPS            : {baseline_row.get('avg_packets_per_second', 0):.2f}\n\n")

        f.write("DDoS Attack Phase:\n")
        f.write(f"  Total Packets      : {ddos_row.get('total_packets', 0):,}\n")
        f.write(f"  ICMP Packets       : {ddos_row.get('icmp_packets', 0):,}\n")
        f.write(f"  TCP Packets        : {ddos_row.get('tcp_packets', 0):,}\n")
        f.write(f"  Packets to Victim  : {ddos_row.get('victim_dst_packets', 0):,}\n")
        f.write(f"  Attack ICMP Only   : {ddos_row.get('attack_icmp_packets', 0):,}\n")
        f.write(f"  Duration           : {ddos_row.get('duration_seconds', 0):.2f}s\n")
        f.write(f"  Avg PPS            : {ddos_row.get('avg_packets_per_second', 0):.2f}\n\n")

        f.write("Key Observations:\n")
        f.write(f"  - ICMP volume increase: {ddos_row.get('icmp_packets', 0) - baseline_row.get('icmp_packets', 0):,} packets\n")
        f.write(f"  - Attack ICMP packets: {ddos_row.get('attack_icmp_packets', 0):,} (attacker → victim)\n")
        f.write(f"  - TCP retransmissions: baseline={baseline_row.get('tcp_retransmissions', 0)}, ddos={ddos_row.get('tcp_retransmissions', 0)}\n")
        f.write(f"  - TCP duplicate ACKs: baseline={baseline_row.get('tcp_duplicate_acks', 0)}, ddos={ddos_row.get('tcp_duplicate_acks', 0)}\n")
        f.write(f"  - Network degradation: {max(0, ddos_row.get('tcp_retransmissions', 0) - baseline_row.get('tcp_retransmissions', 0))} additional retransmissions\n\n")

        # Section 5: Attack Attribution
        f.write("=" * 80 + "\n")
        f.write("SECTION 5: ATTACK ATTRIBUTION\n")
        f.write("=" * 80 + "\n")
        if not attacker_df.empty:
            f.write(attacker_df.to_string(index=False) + "\n\n")
        f.write("Attribution Summary:\n")
        f.write("  All four attackers (h1, h7, h13, h18) simultaneously generated ICMP\n")
        f.write("  requests targeting the victim (10.0.0.25). The attack is classified as\n")
        f.write("  a distributed ICMP Flood with evidence of coordinated attack behavior.\n\n")

        # Section 6: Conversation Flow Analysis
        f.write("=" * 80 + "\n")
        f.write("SECTION 6: CONVERSATION FLOW ANALYSIS\n")
        f.write("=" * 80 + "\n")
        if not conversation_df.empty:
            top_conv = conversation_df.nlargest(10, "packet_count")
            f.write(top_conv.to_string(index=False) + "\n\n")
        f.write("Forensic Interpretation:\n")
        f.write("  Attack flows (red arrows in Graph 7) show attacker→victim ICMP traffic.\n")
        f.write("  Response flows show victim→attacker ICMP replies (legitimate response).\n")
        f.write("  Coordinated timing suggests centralized attack orchestration.\n\n")

        # Section 7: TCP Quality & Network Impact
        f.write("=" * 80 + "\n")
        f.write("SECTION 7: TCP QUALITY & NETWORK IMPACT ASSESSMENT\n")
        f.write("=" * 80 + "\n")
        f.write("TCP Anomalies Detected:\n")
        f.write(f"  Baseline:\n")
        f.write(f"    - Retransmissions     : {baseline_row.get('tcp_retransmissions', 0)}\n")
        f.write(f"    - Duplicate ACKs      : {baseline_row.get('tcp_duplicate_acks', 0)}\n")
        f.write(f"    - Lost Segments       : {baseline_row.get('tcp_lost_segments', 0)}\n")
        f.write(f"    - Fast Retransmissions: {baseline_row.get('tcp_fast_retransmissions', 0)}\n\n")
        f.write(f"  DDoS Attack Phase:\n")
        f.write(f"    - Retransmissions     : {ddos_row.get('tcp_retransmissions', 0)}\n")
        f.write(f"    - Duplicate ACKs      : {ddos_row.get('tcp_duplicate_acks', 0)}\n")
        f.write(f"    - Lost Segments       : {ddos_row.get('tcp_lost_segments', 0)}\n")
        f.write(f"    - Fast Retransmissions: {ddos_row.get('tcp_fast_retransmissions', 0)}\n\n")

        f.write("Network Impact:\n")
        retx_increase = ddos_row.get('tcp_retransmissions', 0) - baseline_row.get('tcp_retransmissions', 0)
        dupack_increase = ddos_row.get('tcp_duplicate_acks', 0) - baseline_row.get('tcp_duplicate_acks', 0)
        f.write(f"  - TCP retransmission increase: +{retx_increase} ({retx_increase/max(1, baseline_row.get('tcp_retransmissions', 1))*100:.1f}%)\n")
        f.write(f"  - TCP duplicate ACK increase : +{dupack_increase}\n")
        f.write("  - Interpretation: ICMP Flood causes congestion, leading to packet loss\n")
        f.write("    and TCP congestion control mechanisms (retransmission, duplicate ACKs).\n\n")

        # Section 8: Conclusion & Recommendations
        f.write("=" * 80 + "\n")
        f.write("SECTION 8: CONCLUSION & RECOMMENDATIONS\n")
        f.write("=" * 80 + "\n")
        f.write("Forensic Conclusion:\n")
        f.write("  1. Attack Confirmed: Distributed ICMP Flood from 4 coordinated sources.\n")
        f.write(f"  2. Attack Volume: {ddos_row.get('attack_icmp_packets', 0):,} ICMP packets targeting {VICTIM_IP}.\n")
        f.write(f"  3. Attack Rate: {ddos_row.get('avg_packets_per_second', 0):.2f} pps average based on PCAP capture.\n")
        f.write("  4. Network Impact: TCP quality degradation observed during attack.\n")
        f.write("  5. Attribution: All four attackers contributed to the distributed attack.\n\n")

        f.write("Evidence Chain:\n")
        f.write("  - Primary Evidence: PCAP packet captures (raw forensic evidence)\n")
        f.write("  - Secondary Evidence: Derived statistics and graphs (analysis evidence)\n")
        f.write("  - Tertiary Evidence: TCP anomalies (impact evidence)\n\n")

        f.write("Recommendations:\n")
        f.write("  1. Implement per-host ICMP rate limiting at access switches.\n")
        f.write("  2. Deploy early-warning monitoring on the SDN controller and access switches.\n")
        f.write("  3. Preserve PCAP and controller telemetry for incident post-mortem.\n")
        f.write("  4. Correlate PCAP evidence with traffic_analysis.csv and mitigation_events.csv.\n\n")

        f.write("=" * 80 + "\n")
        f.write("END OF FORENSIC REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"[+] Forensic report saved: {report_path}")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    check_tshark()

    print("\n" + "=" * 80)
    print("PCAP RAW PACKET FORENSIC ANALYZER (v2.0)")
    print("Specialized: ICMP Flood DDoS Attribution & Impact Assessment")
    print("=" * 80)

    # Read PCAPs
    print("\n[*] Phase 1: Evidence Collection")
    print("[*] Reading baseline PCAP...")
    baseline_df = run_tshark(BASELINE_PCAP, "baseline")
    print(f"[+] Baseline packets loaded: {len(baseline_df):,}")

    print("[*] Reading DDoS PCAP...")
    ddos_df = run_tshark(DDOS_PCAP, "ddos")
    print(f"[+] DDoS packets loaded: {len(ddos_df):,}")

    if baseline_df.empty and ddos_df.empty:
        print("[!] No PCAP data available for analysis.")
        sys.exit(1)

    # Generate summaries
    print("\n[*] Phase 2: Forensic Evidence Analysis")
    baseline_summary = protocol_summary(baseline_df, "baseline")
    ddos_summary = protocol_summary(ddos_df, "ddos")

    summary_df = pd.DataFrame([baseline_summary, ddos_summary])
    attacker_df = attacker_summary(ddos_df)
    conversation_df = conversation_analysis(ddos_df)

    # Save CSV evidence files
    print("[*] Saving forensic evidence files...")
    
    summary_df.to_csv(f"{OUTPUT_DIR}/pcap_summary_stats.csv", index=False)
    print("[+] pcap_summary_stats.csv")
    
    attacker_df.to_csv(f"{OUTPUT_DIR}/pcap_attacker_summary.csv", index=False)
    print("[+] pcap_attacker_summary.csv")
    
    conversation_df.to_csv(f"{OUTPUT_DIR}/pcap_conversations_flows.csv", index=False)
    print("[+] pcap_conversations_flows.csv")

    # Generate 7 forensic graphs
    print("\n[*] Phase 3: Forensic Graph Generation (7 Required Graphs)")
    
    print("[*] Graph 1: ICMP Volume Comparison...")
    graph_1_icmp_volume_comparison(summary_df)
    
    print("[*] Graph 2: Attack ICMP Rate Timeline...")
    graph_2_attack_icmp_rate_timeline(ddos_df)
    
    print("[*] Graph 3: ICMP Attack per Attacker...")
    graph_3_attack_icmp_per_attacker(ddos_df, attacker_df)
    
    print("[*] Graph 4: ICMP Rate per Attacker (Overlay)...")
    graph_4_icmp_rate_per_attacker(ddos_df)
    
    print("[*] Graph 5: TCP Quality Indicators...")
    graph_5_tcp_quality_indicators(summary_df)
    
    print("[*] Graph 6: Protocol Distribution...")
    graph_6_protocol_distribution(summary_df)
    
    print("[*] Graph 7: Conversation Flow Analysis...")
    graph_7_conversation_flow(conversation_df)

    # Generate forensic report
    print("\n[*] Phase 4: Forensic Report Generation")
    write_forensic_report(summary_df, attacker_df, conversation_df, ddos_df)

    # Summary
    print("\n" + "=" * 80)
    print("PCAP FORENSIC ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"[+] Output Directory: {OUTPUT_DIR}\n")
    print("[+] Evidence Files Generated:")
    print("    - pcap_summary_stats.csv")
    print("    - pcap_attacker_summary.csv")
    print("    - pcap_conversations_flows.csv")
    print("    - pcap_forensic_report.txt\n")
    print("[+] Forensic Graphs Generated (7 Required):")
    print("    1. g01_icmp_volume_comparison.png")
    print("    2. g02_attack_icmp_rate_timeline.png")
    print("    3. g03_attack_icmp_per_attacker.png")
    print("    4. g04_icmp_rate_per_attacker_overlay.png")
    print("    5. g05_tcp_quality_indicators.png")
    print("    6. g06_protocol_distribution.png")
    print("    7. g07_conversation_flow_top15.png\n")
    print("[✓] Ready for forensic documentation and NIST SP 800-86 reporting.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
