from cfgparser.packet import Packet
from colorama import Fore

class SingletonMetaClass(type):
    def __init__(cls,name,bases,dict):
        super(SingletonMetaClass,cls)\
          .__init__(name,bases,dict)
        original_new = cls.__new__
        def my_new(cls,*args,**kwds):
            if cls.instance == None:
                cls.instance = \
                  original_new(cls,*args,**kwds)
            return cls.instance
        cls.instance = None
        cls.__new__ = staticmethod(my_new)

class Runner(object):
    __metaclass__ = SingletonMetaClass
    def __init__(self, ipaddrs, first_non_local_ip, iproutes, ipsets, iptables):
        self.ipaddrs = ipaddrs
        self.first_non_local_ip = first_non_local_ip
        self.iproutes = iproutes
        self.ipsets = ipsets
        self.iptables = iptables

    def RunIncommingPacket(self, packet):
        if self.process_packet_in_chain(packet, "raw", "PREROUTING") == "DROP":
            return
        if self.process_packet_in_chain(packet, "mangle", "PREROUTING") == "DROP":
            return

        # localhost source?
        if not self.localhost_ip(packet.source):
            print("NOT LOCAL SOURCE PACKET")
            if self.process_packet_in_chain(packet, "nat", "PREROUTING") == "DROP":
                return
            
            # routing decision
            if not self.routing_decision(packet):
                return

            # localhost dest?
            if not self.localhost_ip(packet.dest):
                print(Fore.RED + "IS FORWARD PACKET")
                self.RunForwardPacket(packet)
                return
        
        if self.process_packet_in_chain(packet, "mangle", "INPUT") == "DROP":
            return
        if self.process_packet_in_chain(packet, "filter", "INPUT") == "DROP":
            return
        if self.process_packet_in_chain(packet, "nat", "INPUT") == "DROP":
            return

        print("LOCAL PROCESSING")
        print(packet)
    
    def RunForwardPacket(self, packet):
        if self.process_packet_in_chain(packet, "mangle", "FORWARD") == "DROP":
            return
        if self.process_packet_in_chain(packet, "filter", "FORWARD") == "DROP":
            return
        if self.process_packet_in_chain(packet, "mangle", "POSTROUTING") == "DROP":
            return

        # localhost dest?
        if not self.localhost_ip(packet.dest):
            if self.process_packet_in_chain(packet, "nat", "POSTROUTING") == "DROP":
                return

        print("FORWARD OUTGOING PACKET")
        print(packet)
    
    def RunLocalGenPacket(self, packet):
        # routing decision
        if not self.routing_decision(packet):
            return

        if self.process_packet_in_chain(packet, "raw", "OUTPUT") == "DROP":
            return
        if self.process_packet_in_chain(packet, "mangle", "OUTPUT") == "DROP":
            return
        if self.process_packet_in_chain(packet, "nat", "OUTPUT") == "DROP":
            return

        # routing decision
        if not self.routing_decision(packet):
            return

        if self.process_packet_in_chain(packet, "filter", "FORWARD") == "DROP":
            return
        if self.process_packet_in_chain(packet, "mangle", "POSTROUTING") == "DROP":
            return

        # localhost dest?
        if not self.localhost_ip(packet.dest):
            if self.process_packet_in_chain(packet, "nat", "POSTROUTING") == "DROP":
                return

        print("OUTGOING PACKET")
        print(packet)

    def process_packet_in_chain(self, packet, table, chain):
        print("TABLE: " + table + " CHAIN: " + chain)
        packet.stack_init(chain)
        while not packet.stack_complete():
            chain = packet.stack_top()["chain"]
            index = packet.stack_top()["idx"]

            # chian complete?
            if index == len(self.iptables[table][chain]["rules"]):
                packet.stack_pop()
                if packet.stack:
                    packet.stack_next_rule()
                continue

            rule = self.iptables[table][chain]["rules"][index]
            # print(rule.raw)

            # basic match?
            if not rule.match(packet):
                rule.not_match_print(table)
                packet.stack_next_rule()
                continue
            
            # extension match?
            if not rule.ext_match(packet, self):
                rule.not_match_print(table)
                packet.stack_next_rule()
                continue
            
            rule.match_print(table)
            # process target
            result = rule.target.process(packet, self)
            if result != "CONTINUE":
                return result
        
        return self.iptables[table][chain]["policy"]

    def localhost_ip(self, ip):
        for dev in self.ipaddrs.values():
            for addrs in dev:
                if addrs["ip"] == ip:
                    return True
        return False

    def routing_decision(self, packet):
        for route in self.iproutes:
            if packet.dest in route["dest"]:
                if route["blackhole"]:
                    print(Fore.RED + "BLACKHOLE ROUTE FOR PACKET, DEST: " + str(packet.dest))
                    return False
                packet.oface = route["dev"]
                return True
        print(Fore.RED + "NO ROUTE FOR PACKET, DEST: " + str(packet.dest))
        return False

    def get_masquerade_ip(self, ip):
        for route in self.iproutes:
            if ip in route["dest"]:
                if route["src"]:
                    return route["src"]
                return self.ipaddrs[route["dev"]][0]["ip"]

    def ip_in_set(self, ip, setname):
        for subnet in self.ipsets[setname]:
            if ip in subnet:
                return True
        return False