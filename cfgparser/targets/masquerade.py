import ipaddress
from colorama import Fore

# http://ipset.netfilter.org/iptables-extensions.man.html#lbDF

class Masquerade(object):
    def __init__(self, raw):
        self.port = 0
        fields = raw.split()
        for i in range(len(fields)):
            if fields[i] == "--to-ports":
                if "-" in fields[i+1]:
                    self.port = int(fields[i+1].split("-")[0])
                else:
                    self.port = int(fields[i+1])
    
    def process(self, packet, runner):
        original_ip, oritinal_port = packet.source, packet.sport
        if self.port:
            packet.sport = self.port
        
        if runner.localhost_ip(packet.dest):
            packet.source = ipaddress.ip_address(runner.first_non_local_ip)
        else:
            packet.source = runner.get_masquerade_ip(packet.dest)

        print(Fore.RED + "TARGET MASQUERADE: " + str(original_ip) + ":" + str(oritinal_port) + " => " + str(packet.source) + ":" + str(packet.sport))
        return "ACCEPT"