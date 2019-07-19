# http://ipset.netfilter.org/iptables-extensions.man.html#lbAO

class Conntrack(object):
    def __init__(self, raw):
        self.statelist = raw.split()[3].split(",")
    
    def match(self, packet, runner):
        return packet.ctstate in self.statelist