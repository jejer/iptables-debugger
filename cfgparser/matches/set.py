# http://ipset.netfilter.org/iptables-extensions.man.html#lbCA

class Set(object):
    def __init__(self, raw):
        self.setname = ""
        self.invert = False
        self.flags = []

        fields = raw.split()
        for i in range(len(fields)):
            if fields[i] == "--match-set":
                if fields[i-1] == "!":
                    self.invert = True
                self.setname = fields[i+1]
                self.flags = fields[i+2].split(",")
    
    def match(self, packet, runner):
        if "src" in self.flags:
            if (not self.invert) and (not runner.ip_in_set(packet.source, self.setname)):
                return False
            if self.invert and runner.ip_in_set(packet.source, self.setname):
                return False
        if "dst" in self.flags:
            if (not self.invert) and (not runner.ip_in_set(packet.dest, self.setname)):
                return False
            if self.invert and runner.ip_in_set(packet.dest, self.setname):
                return False
        return True