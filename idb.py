from prompt_toolkit import prompt
from cfgparser.packet import Packet
from runner.runner import Runner
from cfgparser.iptables import ParseIPTables
from cfgparser.ipaddrs import ParseIPAddrs
from cfgparser.iproutes import ParseIPRoutes
from cfgparser.ipsets import ParseIPSets
from colorama import init

if __name__ == '__main__':
    init(autoreset=True)
    # answer = prompt('Give me some input: ')
    # print('You said: %s' % answer)

    tables = ParseIPTables(r'examples\iptables.txt')
    addrs, non_local_ip = ParseIPAddrs(r'examples\ipaddrs.txt')
    routes = ParseIPRoutes(r'examples\iproutes.txt')
    sets = ParseIPSets(r'examples\ipsets.txt')

    p = Packet()
    # p.set_source("192.168.199.10").set_dest("192.168.199.14").dport = 2379
    # p.iface = "cali30b5015dbf7"
    # p.set_source("192.16.1.51").set_dest("192.16.1.29").dport = 2379
    # p.set_source("192.16.1.51").set_dest("10.254.0.1").dport = 443
    # Runner(addrs, non_local_ip, routes, sets, tables).RunIncommingPacket(p)
    p.set_dest("192.16.1.51").dport = 2379
    Runner(addrs, non_local_ip, routes, sets, tables).RunLocalGenPacket(p)