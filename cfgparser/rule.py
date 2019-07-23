import ipaddress
from colorama import Fore

class Rule(object):
    def __init__(self, raw):
        self.iface = ""
        self.invert_iface = False
        self.oface = ""
        self.invert_oface = False
        self.source = []
        self.invert_source = False
        self.dest = []
        self.invert_dest = False
        self.protocol = ""
        self.invert_protocol = False
        self.matches = []
        self.target = None
        self.raw = raw
    
    def match(self, packet):
        # check iface
        if self.iface and (not self.invert_iface) and self.iface[-1] != "+":
            if packet.iface != self.iface:
                return False
        if self.iface and (not self.invert_iface) and self.iface[-1] == "+":
            if packet.iface[:len(self.iface)-1] != self.iface[:len(self.iface)-1]:
                return False
        if self.iface and self.invert_iface and self.iface[-1] != "+":
            if packet.iface == self.iface:
                return False
        if self.iface and self.invert_iface and self.iface[-1] == "+":
            if packet.iface[:len(self.iface)-1] == self.iface[:len(self.iface)-1]:
                return False

        # check oface
        if self.oface and (not self.invert_oface) and self.oface[-1] != "+":
            if packet.oface != self.oface:
                return False
        if self.oface and (not self.invert_oface) and self.oface[-1] == "+":
            if packet.oface[:len(self.oface)-1] != self.oface[:len(self.oface)-1]:
                return False
        if self.oface and self.invert_oface and self.oface[-1] != "+":
            if packet.oface == self.oface:
                return False
        if self.oface and self.invert_oface and self.oface[-1] == "+":
            if packet.oface[:len(self.oface)-1] == self.oface[:len(self.oface)-1]:
                return False

        # check source
        if self.source and (not self.invert_source) and (packet.source not in self.source):
            return False
        if self.source and self.invert_source and (packet.source in self.source):
            return False

        # check dest
        if self.dest and (not self.invert_dest) and (packet.dest not in self.dest):
            return False
        if self.dest and self.invert_dest and (packet.dest in self.dest):
            return False

        # check protocol
        if self.protocol and (not self.invert_protocol) and (packet.protocol != self.protocol):
            return False
        if self.protocol and self.invert_protocol and (packet.protocol == self.protocol):
            return False

        return True

    def ext_match(self, packet, runner):
        for match in self.matches:
            if not match.match(packet, runner):
                return False
        return True

    def not_match_print(self, table):
        print(Fore.CYAN + "[" + table + "] SKIP " + self.raw)
    def match_print(self, table):
        print(Fore.GREEN + "[" + table + "] " + self.raw)