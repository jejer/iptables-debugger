# http://ipset.netfilter.org/iptables-extensions.man.html#lbBQ

class physdev(object):
    def __init__(self, raw):
        pass
    
    def match(self, packet, runner):
        return False