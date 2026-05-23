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
DIM     = '\033[2m'

RED     = '\033[91m'
GREEN   = '\033[92m'
YELLOW  = '\033[93m'
MAGENTA = '\033[95m'
CYAN    = '\033[96m'
WHITE   = '\033[97m'

LIME    = '\033[38;5;118m'
SKY     = '\033[38;5;117m'
GOLD    = '\033[38;5;220m'
TEAL    = '\033[38;5;43m'

def c(text, *styles):
    return ''.join(styles) + str(text) + RESET

def out(text):
    sys.stdout.write(text + '\n')
    sys.stdout.flush()

def section(icon, title, color=CYAN):
    out(c(f'  {icon}  {title}', BOLD + color))


# =============================================================================
# TOPOLOGY
# =============================================================================
class EnterpriseTreeTopo(Topo):
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
            2: range(1, 6),
            3: range(6, 11),
            4: range(11, 16),
            5: range(16, 21),
            6: range(21, 26),
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

VICTIM  = {'h25': {'ip': '10.0.0.25', 'switch': 's6'}}

NORMALS = {f'h{i}': f'10.0.0.{i}' for i in range(1, 26)
           if f'h{i}' not in ATTACKERS and f'h{i}' not in VICTIM}


# =============================================================================
# PRINT HELPERS
# =============================================================================
def print_banner():
    W = 78
    out('')
    out(c('🔒  SDN ICMP Flood Detection & Mitigation System'.center(W), BOLD + WHITE))
    out(c('Enterprise Tree Topology  ·  OpenFlow 1.3'.center(W), SKY))


def print_topology(net):
    section('📡', 'Topology', SKY)

    info_rows = [
        ('Core',   c('s1', BOLD + TEAL),        c('(DPID=1)', DIM + WHITE)),
        ('Access', c('s2 – s6', BOLD + TEAL),   c('(DPID=2–6)', DIM + WHITE)),
        ('Hosts',  c('25 total', BOLD + WHITE),  c('(h1–h25, 5 per switch)', DIM + WHITE)),
        ('Subnet', c('10.0.0.0/24', BOLD + WHITE), c('· OpenFlow 1.3', DIM + WHITE)),
    ]
    for label, val, note in info_rows:
        out(c(f'  {label:<8}', DIM + WHITE) + val + '  ' + note)

    out('')

    T = DIM + CYAN
    col1, col2, col3 = 10, 14, 32

    def cell(value, width, style, align='<'):
        return c(f' {value:{align}{width - 1}}', style)

    def row(left, middle, right, middle_style=BOLD + WHITE, right_style=WHITE):
        return (c('  ', T) + cell(left, col1, BOLD + TEAL) +
                cell(middle, col2, middle_style) +
                cell(right, col3, right_style, '^'))

    out(c('  ', T) + cell('Switch', col1, BOLD + WHITE) +
        cell('Hosts', col2, BOLD + WHITE) +
        cell('Role', col3, BOLD + WHITE, '^'))

    rows = [
        ('s2', 'h1–h5',   RED,     'h1 = Attacker 🔴'),
        ('s3', 'h6–h10',  RED,     'h7 = Attacker 🔴'),
        ('s4', 'h11–h15', RED,     'h13 = Attacker 🔴'),
        ('s5', 'h16–h20', RED,     'h18 = Attacker 🔴'),
        ('s6', 'h21–h25', MAGENTA, 'h25 = Victim 🎯'),
    ]

    for sw, hosts, color, note in rows:
        out(row(sw, hosts, note, right_style=color))


def verify_and_print_status(net):
    section('✅', 'Network Status', LIME)

    ctrl = net.controllers[0]
    out(c('  Controller  ', DIM + WHITE) +
        c(ctrl.name, BOLD + GREEN) +
        c('  →  ', DIM + WHITE) +
        c(f'{ctrl.ip}:{ctrl.port}', BOLD + LIME))

    all_connected = all(
        'tcp:127.0.0.1:6653' in sw.cmd(f'ovs-vsctl get-controller {sw.name}').strip()
        for sw in net.switches
    )
    all_of13 = all(
        'OpenFlow13' in sw.cmd(f'ovs-vsctl get bridge {sw.name} protocols').strip()
        for sw in net.switches
    )

    conn_str = (c('6/6 connected', BOLD + LIME) if all_connected
                else c('⚠  check controller', BOLD + YELLOW))
    of_str   = (c('OpenFlow 1.3 ✓', BOLD + LIME) if all_of13
                else c('⚠  protocol mismatch', BOLD + YELLOW))

    out(c('  Switches    ', DIM + WHITE) + conn_str + c('  ·  ', DIM + WHITE) + of_str)
    out(c('  Logging     ', DIM + WHITE) + c('/home/kali/sdn-icmp/logs/', BOLD + SKY))
    out(c('  6 switches  ·  25 hosts  (4 attacker · 20 normal · 1 victim)', DIM + WHITE))

    if not all_connected:
        out('')
        out(c('  ⚠  Pastikan Ryu berjalan:', BOLD + YELLOW))
        out(c('     sudo ryu-manager controller/controller.py', YELLOW))


def print_cheatsheet():
    out('')
    out(c('  pingall', SKY))
    out(c('  h2 ping -i 1 10.0.0.25 &', LIME))
    out(c('  h1 hping3 --icmp -i u1000 10.0.0.25 &', RED))
    out(c('  h1 pkill hping3', GOLD))
    out(c('  sh ovs-ofctl -O OpenFlow13 dump-flows s1', SKY))
    out('')


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

    info(c('*** Adding Ryu controller (127.0.0.1:6653)...\n', DIM + CYAN))
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info(c('*** Building & starting network...\n', DIM + CYAN))
    net.build()
    net.start()
    time.sleep(1)

    print_banner()
    print_topology(net)
    verify_and_print_status(net)
    print_cheatsheet()

    info(c('*** Mininet CLI ready\n', BOLD + LIME))
    CLI(net)

    info(c('\n*** Stopping network...\n', DIM + RED))
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()