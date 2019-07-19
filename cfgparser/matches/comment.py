# http://ipset.netfilter.org/iptables-extensions.man.html#lbAJ

class Comment(object):
    def __init__(self, raw):
        self.comment = raw[21:]
    
    def match(self, packet, runner):
        return True