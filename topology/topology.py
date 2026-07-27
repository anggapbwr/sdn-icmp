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
    out('')
    out(c('🔒  SDN ICMP Flood Detection & Mitigation System', BOLD + WHITE))
    out(c('Enterprise Tree Topology  ·  OpenFlow 1.3', SKY))
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

    info(c('*** Mininet CLI ready\n', BOLD + LIME))
    CLI(net)

    info(c('\n*** Stopping network...\n', DIM + RED))
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()