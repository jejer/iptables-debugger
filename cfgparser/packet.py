import ipaddress

# class Packet(object):
#     def __init__(self, s, d, dp, p=-1, i="", o="", sp=9527, t="incomming", mark=0, state="NEW"):
#         self.protocol = p
#         self.iface = i
#         self.oface = o
#         self.source = ipaddress.ip_address(s)
#         self.dest = ipaddress.ip_address(d)
#         self.sport = sp
#         self.dport = dp
#         self.type = t
#         self.nfmark = mark
#         self.ctstate = state
#         self.stack = []

class Packet(object):
    def __init__(self):
        self.iface = ""
        self.oface = ""
        self.source = ipaddress.ip_address("0.0.0.0")
        self.dest = ipaddress.ip_address("0.0.0.0")
        self.protocol = "tcp"
        self.sport = 0
        self.dport = 0
        self.nfmark = 0
        self.ctstate = "NEW"
        self.type = "incomming"
        self.stack = []
    
    def __str__(self):
        return "[Packet] iface: %s, oface: %s, source: %s, dest: %s, protocol: %s, sport: %d, dport: %d, nfmark: %s" % (
            self.iface, self.oface, str(self.source), str(self.dest), self.protocol, self.sport, self.dport, hex(self.nfmark)
        )
    
    def set_source(self, ip):
        self.source = ipaddress.ip_address(ip)
        return self
    def set_dest(self, ip):
        self.dest = ipaddress.ip_address(ip)
        return self

    def stack_init(self, chain):
        self.stack = [{"chain": chain, "idx": 0}]
        print(self.stack)
        return self
    def stack_top(self):
        return self.stack[len(self.stack)-1]
    def stack_next_rule(self):
        last = self.stack.pop()
        last["idx"] += 1
        self.stack.append(last)
        print(self.stack)
        return self
    def stack_pop(self):
        self.stack.pop()
        print(self.stack)
        return self
    def stack_push(self, chain):
        self.stack.append({"chain": chain, "idx": 0})
        print(self.stack)
        return self
    def stack_complete(self):
        return len(self.stack) == 0