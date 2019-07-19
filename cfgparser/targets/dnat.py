import ipaddress
from colorama import Fore

# http://ipset.netfilter.org/iptables-extensions.man.html#lbCV

class DNAT(object):
    def __init__(self, raw):
        if ":" in raw.split()[3]:
            self.ip = raw.split()[3].split(":")[0]
            self.port = int(raw.split()[3].split(":")[1])
        else:
            self.ip = raw.split()[3]
            self.port = 0
    
    def process(self, packet, runner):
        original_ip, oritinal_port = packet.dest, packet.dport
        packet.dest = ipaddress.ip_address(self.ip)
        if self.port:
            packet.dport = self.port

        print(Fore.RED + "TARGET DNAT: " + str(original_ip) + ":" + str(oritinal_port) + " => " + str(packet.dest) + ":" + str(packet.dport))
        return "ACCEPT"