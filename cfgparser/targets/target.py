from cfgparser.targets.mark import Mark
from cfgparser.targets.dnat import DNAT
from cfgparser.targets.masquerade import Masquerade
from colorama import Fore

# http://ipset.netfilter.org/iptables.man.html

def NewTarget(target, raw):
    unsupported = [
        "AUDIT",
        "CHECKSUM",
        "CLASSIFY",
        "CLUSTERIP",
        "CONNMARK",
        "CONNSECMARK",
        "CT",
        # "DNAT",
        "DNPT",
        "DSCP",
        "ECN",
        "HL",
        "HMARK",
        "IDLETIMER",
        "LED",
        "LOG",
        # "MARK",
        # "MASQUERADE",
        "MIRROR",
        "NETMAP",
        "NFLOG",
        "NFQUEUE",
        "NOTRACK",
        "RATEEST",
        "REDIRECT",
        "REJECT",
        "REJECT",
        "SAME",
        "SECMARK",
        "SET",
        "SNAT",
        "SNPT",
        "TCPMSS",
        "TCPOPTSTRIP",
        "TEE",
        "TOS",
        "TPROXY",
        "TRACE",
        "TTL",
        "ULOG",
    ]
    if target == "ACCEPT":
        return Accept()
    elif target == "DROP":
        return Drop()
    elif target == "QUEUE":
        return Trivial(target, raw)
    elif target == "RETURN":
        return Return()
    elif target == "MARK":
        return Mark(raw)
    elif target == "DNAT":
        return DNAT(raw)
    elif target == "MASQUERADE":
        return Masquerade(raw)
    elif target in unsupported:
        print("UNSUPPORTED TARGET: " + target + " [" + raw + "]")
        return Trivial(target, raw)
    else:
        return Jump(target)

def NewGoto(target, raw):
    return Goto(target)

class Accept(object):
    def process(self, packet, runner):
        print(Fore.RED + "TARGET ACCEPT")
        return "ACCEPT"

class Drop(object):
    def process(self, packet, runner):
        print(Fore.RED + "TARGET DROP")
        return "DROP"

class Return(object):
    def process(self, packet, runner):
        packet.stack_pop().stack_next_rule()
        print(Fore.RED + "TARGET RETURN")
        return "CONTINUE"

class Jump(object):
    def __init__(self, chain):
        self.chain = chain
    def process(self, packet, runner):
        packet.stack_push(self.chain)
        print(Fore.RED + "TARGET JUMP: " + self.chain)
        return "CONTINUE"

class Goto(object):
    def __init__(self, chain):
        self.chain = chain
    def process(self, packet, runner):
        packet.stack_pop().stack_push(self.chain)
        print(Fore.RED + "TARGET GOTO: " + self.chain)
        return "CONTINUE"

class Trivial(object):
    def __init__(self, name, raw):
        self.name = name
        self.raw = raw
    def process(self, packet, runner):
        packet.stack_next_rule()
        print(Fore.RED + "UNSUPPORTED TARGET " + self.name + " : " + self.raw)
        return "CONTINUE"
