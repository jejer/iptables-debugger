from cfgparser.matches.comment import Comment
from cfgparser.matches.mark import Mark
from cfgparser.matches.multiport import Multiport
from cfgparser.matches.conntrack import Conntrack
from cfgparser.matches.addrtype import Addrtype
from cfgparser.matches.tcp import TCP
from cfgparser.matches.udp import UDP
from cfgparser.matches.set import Set
from cfgparser.matches.statistic import Statistic
from cfgparser.matches.physdev import physdev

def NewMatch(module, raw):
    if module == "comment":
        return Comment(raw)
    if module == "mark":
        return Mark(raw)
    if module == "multiport":
        return Multiport(raw)
    if module == "conntrack":
        return Conntrack(raw)
    if module == "addrtype":
        return Addrtype(raw)
    if module == "tcp":
        return TCP(raw)
    if module == "udp":
        return UDP(raw)
    if module == "set":
        return Set(raw)
    if module == "statistic":
        return Statistic(raw)
    if module == "physdev":
        return physdev(raw)
    else:
        print("UNSUPPORTED MODULE: " + module + " [" + raw + "]")
    return None