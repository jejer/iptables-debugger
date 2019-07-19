# http://ipset.netfilter.org/iptables-extensions.man.html#lbAE

class Addrtype(object):
    def __init__(self, raw):
        self.src_type = ""
        self.invert_src_type = False
        self.dst_type = ""
        self.invert_dst_type = False

        fields = raw.split()
        for i in range(len(fields)):
            if fields[i] == "--src-type":
                self.src_type = fields[i+1]
                if fields[i-1] == "!":
                    self.invert_src_type = True
            if fields[i] == "--dst-type":
                self.dst_type = fields[i+1]
                if fields[i-1] == "!":
                    self.invert_dst_type = True

    def match(self, packet, runner):
        if self.src_type == "LOCAL" and (not self.invert_src_type) and (not runner.localhost_ip(packet.source)):
            return False
        if self.src_type == "LOCAL" and self.invert_src_type and runner.localhost_ip(packet.source):
            return False
        if self.dst_type == "LOCAL" and (not self.invert_dst_type) and (not runner.localhost_ip(packet.dest)):
            return False
        if self.dst_type == "LOCAL" and self.invert_dst_type and runner.localhost_ip(packet.dest):
            return False
        return True