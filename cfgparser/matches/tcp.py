# http://ipset.netfilter.org/iptables-extensions.man.html#lbCF

class TCP(object):
    def __init__(self, raw):
        self.sports = []
        self.invert_sports = False
        self.dports = []
        self.invert_dports = False

        fields = raw.split()
        for i in range(len(fields)):
            if fields[i] == "--source-port" or fields[i] == "--sport":
                if fields[i-1] == "!":
                    self.invert_sports = True
                if ":" in fields[i+1]:
                    start = int(fields[i+1].split(":")[0])
                    end = int(fields[i+1].split(":")[1])
                    for p in range(start, end+1):
                        self.sports.append(p)
                else:
                    self.sports.append(int(fields[i+1]))

            if fields[i] == "--destination-port" or fields[i] == "--dport":
                if fields[i-1] == "!":
                    self.invert_dports = True
                if ":" in fields[i+1]:
                    start = int(fields[i+1].split(":")[0])
                    end = int(fields[i+1].split(":")[1])
                    for p in range(start, end+1):
                        self.dports.append(p)
                else:
                    self.dports.append(int(fields[i+1]))
    
    def match(self, packet, runner):
        match = True
        if self.sports:
            if (not self.invert_sports) and (packet.sport not in self.sports):
                match = False
            if self.invert_sports and (packet.sport in self.sports):
                match = False
        if self.dports:
            if (not self.invert_dports) and (packet.dport not in self.dports):
                match = False
            if self.invert_dports and (packet.dport in self.dports):
                match = False
        return match