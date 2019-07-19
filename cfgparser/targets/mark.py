from colorama import Fore
# http://ipset.netfilter.org/iptables-extensions.man.html#lbDE

class Mark(object):
    def __init__(self, raw):
        self.op = raw.split()[2]
        if "/" in raw.split()[3]:
            self.value = int(raw.split()[3].split("/")[0], 0)
            self.mask = int(raw.split()[3].split("/")[1], 0)
        else:
            self.value = int(raw.split()[3], 0)
            self.mask = int("0xFFFFFFFF", 0)
    
    def process(self, packet, runner):
        original_mark = packet.nfmark
        if self.op == "--set-xmark":
            packet.nfmark = (packet.nfmark & (self.mask ^ 0xFFFFFFFF)) ^ self.value
        if self.op == "--set-mark":
            packet.nfmark = (packet.nfmark & (self.mask ^ 0xFFFFFFFF)) | self.value

        packet.stack_next_rule()
        print(Fore.RED + "TARGET MARK: " + hex(original_mark) + " => " + hex(packet.nfmark))
        return "CONTINUE"