import re
import ipaddress

# iproutes: [{dest, dev, src, metric, blackhole}]
def ParseIPRoutes(filename):
    devre = re.compile(r".* dev (?P<dev>\S+) .*$")
    srcre = re.compile(r".* src (?P<src>\S+) .*$")
    metricre = re.compile(r".* metric (?P<metric>\S+) .*$")
    iproutes = []

    with open(filename, "r") as file:
        for line in file:
            route = {"dest": None, "dev": "", "src": None, "metric": 0, "blackhole": False}
            fields = line.split()

            if fields[0] == "blackhole":
                route["blackhole"] = True
                route["dest"] = ipaddress.ip_network(fields[1])
                iproutes.append(route)
                continue
            
            if fields[0] == "default":
                route["dest"] = ipaddress.ip_network("0.0.0.0/0")
            else:
                try:
                    route["dest"] = ipaddress.ip_network(fields[0])
                except:
                    continue

            m = devre.match(line)
            if m:
                route["dev"] = m.group("dev")
            m = srcre.match(line)
            if m:
                route["src"] = m.group("src")
            m = metricre.match(line)
            if m:
                route["metric"] = int(m.group("metric"))

            iproutes.append(route)

    # https://serverfault.com/questions/648276/routing-selection-specificity-vs-metric
    iproutes.sort(key=lambda route: route["metric"])
    iproutes.sort(key=lambda route: route["dest"].prefixlen, reverse=True)

    return iproutes
