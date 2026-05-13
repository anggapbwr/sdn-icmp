#!/usr/bin/python3
# =============================================================================
# SDN ICMP Flood Detection — Enterprise Tree Topology
# 6 Switches | 25 Hosts | 4 Attackers | 1 Victim | OpenFlow 1.3
# =============================================================================

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
import time
import sys

# =============================================================================
# ANSI Colors
# =============================================================================
RESET   = '\033[0m'
BOLD    = '\033[1m'
RED     = '\033[91m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
BLUE    = '\033[94m'
MAGENTA = '\033[95m'
CYAN    = '\033[96m'

def c(text, color):
    return f"{color}{text}{RESET}"

def out(text):
    sys.stdout.write(text + '\n')
    sys.stdout.flush()

def sep():
    out(c("─" * 80, CYAN))

def header(title):
    out("")
    sep()
    out(c(f"  {title}", BOLD + CYAN))
    sep()


# =============================================================================
# TOPOLOGY
# =============================================================================
class EnterpriseTreeTopo(Topo):
    """
    1 Core Switch (s1) + 5 Access Switches (s2-s6)
    25 Hosts — 5 per access switch
    Attacker : h1(s2), h7(s3), h13(s4), h18(s5)
    Victim   : h25(s6)
    """
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13', dpid='0000000000000001')

        switches = {}
        for i in range(2, 7):
            switches[i] = self.addSwitch(
                f's{i}', protocols='OpenFlow13',
                dpid=f'000000000000000{i}'
            )
            self.addLink(s1, switches[i])

        host_ranges = {
            2: range(1, 6),    # h1-h5
            3: range(6, 11),   # h6-h10
            4: range(11, 16),  # h11-h15
            5: range(16, 21),  # h16-h20
            6: range(21, 26),  # h21-h25
        }

        for sw_id, hosts in host_ranges.items():
            for i in hosts:
                self.addLink(
                    self.addHost(f'h{i}', ip=f'10.0.0.{i}/24'),
                    switches[sw_id]
                )


# =============================================================================
# METADATA
# =============================================================================
ATTACKERS = {
    'h1':  {'ip': '10.0.0.1',  'switch': 's2'},
    'h7':  {'ip': '10.0.0.7',  'switch': 's3'},
    'h13': {'ip': '10.0.0.13', 'switch': 's4'},
    'h18': {'ip': '10.0.0.18', 'switch': 's5'},
}

VICTIM = {'h25': {'ip': '10.0.0.25', 'switch': 's6'}}

NORMALS = {f'h{i}': f'10.0.0.{i}' for i in range(1, 26)
           if f'h{i}' not in ATTACKERS and f'h{i}' not in VICTIM}


# =============================================================================
# PRINT HELPERS
# =============================================================================
def print_banner():
    out("")
    out(c("=" * 80, CYAN))
    out(c("  🔒 SDN ICMP Flood Detection & Mitigation System", BOLD + CYAN))
    out(c("  Enterprise Tree Topology — OpenFlow 1.3", CYAN))
    out(c("=" * 80, CYAN))

def print_topology(net):
    header("📡 Topology")
    out(c("  Core   : s1 (DPID=1)", BLUE))
    out(c("  Access : s2–s6 (DPID=2–6)", BLUE))
    out(c("  Hosts  : 25 total (h1–h25, 5 per switch)", BLUE))
    out(c("  Subnet : 10.0.0.0/24 | Protocol: OpenFlow 1.3", BLUE))
    out("")
    out(c("  Switch  Hosts         Notes", BOLD + BLUE))
    out(c("  ──────  ──────────    ─────────────────────", BLUE))
    rows = [
        ("s2", "h1  – h5",  "h1  = Attacker 🔴"),
        ("s3", "h6  – h10", "h7  = Attacker 🔴"),
        ("s4", "h11 – h15", "h13 = Attacker 🔴"),
        ("s5", "h16 – h20", "h18 = Attacker 🔴"),
        ("s6", "h21 – h25", "h25 = Victim   🎯"),
    ]
    for sw, hosts, note in rows:
        out(c(f"  {sw}     {hosts:<12}  {note}", BLUE))

def print_roles():
    header("🎭 Host Roles")

    out(c("  🔴 Attackers (4) — ICMP Flood source:", BOLD + RED))
    for host, meta in ATTACKERS.items():
        out(c(f"     {host:<5} {meta['ip']:<15} via {meta['switch']}", RED))

    out("")
    out(c("  🎯 Victim (1) — target of flood:", BOLD + MAGENTA))
    for host, meta in VICTIM.items():
        out(c(f"     {host:<5} {meta['ip']:<15} via {meta['switch']}", MAGENTA))

    out("")
    out(c("  🟢 Normal Hosts (20) — baseline traffic:", BOLD + GREEN))
    normals_display = [(h, ip) for h, ip in sorted(NORMALS.items(),
                        key=lambda x: int(x[0][1:]))]
    # tampilkan 2 kolom
    for i in range(0, len(normals_display), 2):
        left  = f"{normals_display[i][0]:<5} {normals_display[i][1]:<15}"
        right = f"{normals_display[i+1][0]:<5} {normals_display[i+1][1]}" \
                if i+1 < len(normals_display) else ""
        out(c(f"     {left}   {right}", GREEN))

def print_controller(net):
    header("🎛️  Controller")
    for ctrl in net.controllers:
        out(c(f"  ✅ {ctrl.name}  →  {ctrl.ip}:{ctrl.port}", GREEN))

def verify_connections(net):
    header("🔗 Switch ↔ Controller")
    all_ok = True
    for sw in sorted(net.switches, key=lambda x: x.name):
        result = sw.cmd(f'ovs-vsctl get-controller {sw.name}').strip()
        if 'tcp:127.0.0.1:6653' in result:
            out(c(f"  ✅ {sw.name}  connected", GREEN))
        else:
            out(c(f"  ⚠️  {sw.name}  {result or 'not connected'}", YELLOW))
            all_ok = False
    if not all_ok:
        out(c("\n  ⚠️  Pastikan Ryu controller sudah jalan di terminal lain!", YELLOW))
        out(c("     sudo ryu-manager controller/controller.py", YELLOW))

def verify_openflow(net):
    header("📋 OpenFlow Version")
    for sw in sorted(net.switches, key=lambda x: x.name):
        result = sw.cmd(f'ovs-vsctl get bridge {sw.name} protocols').strip()
        if 'OpenFlow13' in result:
            out(c(f"  ✅ {sw.name}  OpenFlow 1.3", GREEN))
        else:
            out(c(f"  ⚠️  {sw.name}  {result or 'unknown'}", YELLOW))

def print_scenario():
    header("🧪 Experiment Commands (copy-paste ke Mininet CLI)")

    out(c("  ── PHASE 0: Setup Server ───────────────────────────────────────", BOLD + BLUE))
    out(c("  h25 python3 -m http.server 80 &", BLUE))
    out(c("  h25 python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',9999)); [(s.recvfrom(1024)) for _ in iter(int,1)]\" &", BLUE))
    out(c("  sleep 3", BLUE))
    out("")

    out(c("  ── PHASE 1: Baseline Normal Traffic ────────────────────────────", BOLD + GREEN))
    out(c("  pingall", GREEN))
    out(c("  sleep 5", GREEN))
    out(c("  h2 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h3 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h6 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h9 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h12 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h14 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h4 ping -c 10 10.0.0.8 &", GREEN))
    out(c("  h10 ping -c 10 10.0.0.16 &", GREEN))
    out(c("  h8 bash -c \"for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do wget -q -O /dev/null http://10.0.0.25/ 2>/dev/null; sleep 1; done\" &", GREEN))
    out(c("  h11 bash -c \"for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do wget -q -O /dev/null http://10.0.0.25/ 2>/dev/null; sleep 1; done\" &", GREEN))
    out(c("  h16 bash -c \"for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do wget -q -O /dev/null http://10.0.0.25/ 2>/dev/null; sleep 1; done\" &", GREEN))
    out(c("  h17 python3 -c \"import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [s.sendto(b'udp-h17',('10.0.0.25',9999)) or time.sleep(1) for _ in range(20)]\" &", GREEN))
    out(c("  h19 python3 -c \"import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [s.sendto(b'udp-h19',('10.0.0.25',9999)) or time.sleep(1) for _ in range(20)]\" &", GREEN))
    out(c("  h22 python3 -c \"import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [s.sendto(b'udp-h22',('10.0.0.25',9999)) or time.sleep(1) for _ in range(20)]\" &", GREEN))
    out(c("  sleep 30", GREEN))
    out("")

    out(c("  ── PHASE 2: ICMP Flood Attack ──────────────────────────────────", BOLD + RED))
    out(c("  h1 hping3 --icmp -i u1000 10.0.0.25 &", RED))
    out(c("  h7 hping3 --icmp -i u1000 10.0.0.25 &", RED))
    out(c("  h13 hping3 --icmp -i u1000 10.0.0.25 &", RED))
    out(c("  h18 hping3 --icmp -i u1000 10.0.0.25 &", RED))
    out(c("  h2 ping -c 30 10.0.0.25 &", GREEN))
    out(c("  h9 ping -c 30 10.0.0.25 &", GREEN))
    out(c("  h8 bash -c \"for i in 1 2 3 4 5 6 7 8 9 10; do wget -q -O /dev/null http://10.0.0.25/ 2>/dev/null; sleep 2; done\" &", GREEN))
    out(c("  sleep 60", RED))
    out("")

    out(c("  ── PHASE 3: Stop Attack & Recovery ─────────────────────────────", BOLD + YELLOW))
    out(c("  h1 pkill hping3", YELLOW))
    out(c("  h7 pkill hping3", YELLOW))
    out(c("  h13 pkill hping3", YELLOW))
    out(c("  h18 pkill hping3", YELLOW))
    out(c("  h3 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h6 ping -c 20 10.0.0.25 &", GREEN))
    out(c("  h21 bash -c \"for i in 1 2 3 4 5 6 7 8 9 10; do wget -q -O /dev/null http://10.0.0.25/ 2>/dev/null; sleep 2; done\" &", GREEN))
    out(c("  sleep 70", YELLOW))
    out("")

    out(c("  ── MONITORING (gunakan kapan saja) ─────────────────────────────", BOLD + CYAN))
    out(c("  sh ovs-ofctl -O OpenFlow13 dump-flows s2", CYAN))
    out(c("  sh ovs-ofctl -O OpenFlow13 dump-meters s2", CYAN))
    out(c("  sh ovs-ofctl -O OpenFlow13 dump-meters s3", CYAN))
    out(c("  sh ovs-ofctl -O OpenFlow13 dump-meters s4", CYAN))
    out(c("  sh ovs-ofctl -O OpenFlow13 dump-meters s5", CYAN))
    out("")

def print_ready():
    header("✅ Network Ready")
    out(c("  6 switches  (1 core + 5 access)  — terhubung ke Ryu", GREEN))
    out(c("  25 hosts    (4 attacker + 20 normal + 1 victim)", GREEN))
    out(c("  OpenFlow 1.3 + Meter rate limiting aktif", GREEN))
    out(c("  CSV logging  →  /home/kali/sdn-icmp/logs/", GREEN))
    out("")
    out(c("  💡 Tip: Buka terminal terpisah untuk monitor log Ryu secara real-time", YELLOW))
    out(c("     tail -f /home/kali/sdn-icmp/logs/traffic_analysis.csv", YELLOW))
    out("")


# =============================================================================
# MAIN
# =============================================================================
def run():
    topo = EnterpriseTreeTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        build=False
    )

    info(c("*** Adding Ryu controller (127.0.0.1:6653)...\n", CYAN))
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info(c("*** Building & starting network...\n", CYAN))
    net.build()
    net.start()
    time.sleep(1)

    # Print semua info
    print_banner()
    print_topology(net)
    print_roles()
    print_controller(net)
    verify_connections(net)
    verify_openflow(net)
    print_ready()
    print_scenario()

    info(c("*** Mininet CLI ready\n", CYAN))
    CLI(net)

    info(c("\n*** Stopping network...\n", RED))
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
