# http://ipset.netfilter.org/iptables-extensions.man.html#lbBK

class Mark(object):
    def __init__(self, raw):
        self.value = 0
        self.mask = 0xFFFFFFFF
        self.invert = False

        fields = raw.split()
        for i in range(len(fields)):
            if fields[i] == "--mark":
                if fields[i-1] == "!":
                    self.invert = True
                if "/" in fields[i+1]:
                    self.value = int(fields[i+1].split("/")[0], 0)
                    self.mask = int(fields[i+1].split("/")[1], 0)
                else:
                    self.value = int(fields[i+1], 0)

    def match(self, packet, runner):
        match = (packet.nfmark & self.mask) == self.value
        if self.invert:
            return not match
        return match