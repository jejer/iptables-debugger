import re
import ipaddress

# ipsets: {setname: [subnet]}
def ParseIPSets(filename):
    setre = re.compile(r"^create (?P<name>\S+) .*$")
    netre = re.compile(r"^add (?P<name>\S+) (?P<subnet>\S+)$")
    current_set = ""
    ipsets = {}

    with open(filename, "r") as file:
        for line in file:
            m = setre.match(line)
            if m:
                current_set = m.group("name")
                ipsets.update({current_set: []})
                continue
            
            m = netre.match(line)
            if m:
                if ":" in m.group("subnet"):
                    continue
                ipsets[current_set].append(ipaddress.ip_network(m.group("subnet")))

    return ipsets
