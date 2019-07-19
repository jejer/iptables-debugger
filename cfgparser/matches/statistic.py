import random

# http://ipset.netfilter.org/iptables-extensions.man.html#lbCD

class Statistic(object):
    def __init__(self, raw):
        self.probability = float(raw.split()[5])
    
    def match(self, packet, runner):
        return random.uniform(0, 1) < self.probability