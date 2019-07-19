import re
import ipaddress

# ipaddrs: {ifname: [{ip, mask}]}
def ParseIPAddrs(filename):
    ifre = re.compile(r"^\d+: (?P<ifname>\S+):.*$")
    ipre = re.compile(r"^    inet (?P<ip>[\d.]+)/(?P<mask>[\d]+) .*$")
    current_if = ""
    first_non_local_ip = None
    ipaddrs = {}

    with open(filename, "r") as file:
        for line in file:
            m = ifre.match(line)
            if m:
                current_if = m.group("ifname")
                ipaddrs.update({current_if: []})
                continue
            
            m = ipre.match(line)
            if m:
                ipaddrs[current_if].append({
                    "ip": ipaddress.ip_address(m.group("ip")),
                    "mask": int(m.group("mask"))
                })
                if not first_non_local_ip and current_if != "lo":
                    first_non_local_ip = ipaddress.ip_address(m.group("ip"))

    return ipaddrs, first_non_local_ip
