from cfgparser.packet import Packet
from runner.runner import Runner
from cfgparser.iptables import ParseIPTables
from cfgparser.ipaddrs import ParseIPAddrs
from cfgparser.iproutes import ParseIPRoutes
from cfgparser.ipsets import ParseIPSets
from colorama import init
from prompt_toolkit.completion import WordCompleter, merge_completers
from prompt_toolkit.shortcuts import CompleteStyle, prompt
from path_completer import PathCompleter
from prompt_toolkit import PromptSession

cfg = {
    "iptables": None,
    "ipaddrs": None,
    "iproutes": None,
    "ipsets": None,
    "non_local_ip": None,
    "packet": Packet(),
}

def bottom_statusbar():
    text = "iptables: {}, ipaddrs: {}, iproutes: {}, ipsets: {} | {}:{} => {}:{}".format(
        "loaded" if cfg["iptables"] else "missing",
        "loaded" if cfg["ipaddrs"] else "missing",
        "loaded" if cfg["iproutes"] else "missing",
        "loaded" if cfg["ipsets"] else "missing",
        cfg["packet"].source, cfg["packet"].sport,
        cfg["packet"].dest, cfg["packet"].dport,
    )
    return text

cmd_completer = WordCompleter([
    'load-dir', 'load-iptables', 'load-ipaddrs', 'load-iproutes', 'load-ipsets',
    'set-source', 'set-dest', 'set-sport', 'set-dport',
    'run-incomming-packet', 'run-localgen-packet', 'exit',
], ignore_case=True)

session = PromptSession()

if __name__ == '__main__':
    init(autoreset=True)
    while True:
        input = session.prompt('> ', bottom_toolbar=bottom_statusbar, completer=merge_completers([PathCompleter(min_input_len=1), cmd_completer]))
        if not input.split():
            continue
        if input.split()[0] == "exit":
            break
        if input.split()[0] == "load-localhost":
            print("not implemented")
            continue
        if input.split()[0] == "load-dir":
            try:
                cfg["iptables"] = ParseIPTables(input.split()[1] + r"/iptables.txt")
                cfg["ipaddrs"], cfg["non_local_ip"] = ParseIPAddrs(input.split()[1] + r"/ipaddrs.txt")
                cfg["iproutes"] = ParseIPRoutes(input.split()[1] + r"/iproutes.txt")
                cfg["ipsets"] = ParseIPSets(input.split()[1] + r"/ipsets.txt")
            except Exception as e:
                print("load config failed. " + str(e))
            continue
        if input.split()[0] == "load-iptables":
            try:
                cfg["iptables"] = ParseIPTables(input.split()[1])
            except Exception as e:
                print("load iptables failed. " + str(e))
            continue
        if input.split()[0] == "load-ipaddrs":
            try:
                cfg["ipaddrs"], cfg["non_local_ip"] = ParseIPAddrs(input.split()[1])
            except Exception as e:
                print("load ipaddrs failed. " + str(e))
            continue
        if input.split()[0] == "load-iproutes":
            try:
                cfg["iproutes"] = ParseIPRoutes(input.split()[1])
            except Exception as e:
                print("load iproutes failed. " + str(e))
            continue
        if input.split()[0] == "load-ipsets":
            try:
                cfg["ipsets"] = ParseIPSets(input.split()[1])
            except Exception as e:
                print("load ipsets failed. " + str(e))
            continue
        if input.split()[0] == "set-source":
            try:
                cfg["packet"].set_source(input.split()[1])
            except Exception as e:
                print("set source ip failed. " + str(e))
            continue
        if input.split()[0] == "set-dest":
            try:
                cfg["packet"].set_dest(input.split()[1])
            except Exception as e:
                print("set dest ip failed. " + str(e))
            continue
        if input.split()[0] == "set-sport":
            try:
                cfg["packet"].sport = int(input.split()[1])
            except Exception as e:
                print("set source port failed. " + str(e))
            continue
        if input.split()[0] == "set-dport":
            try:
                cfg["packet"].dport = int(input.split()[1])
            except Exception as e:
                print("set dest port failed. " + str(e))
            continue
        if input.split()[0] == "run-incomming-packet":
            if (not cfg["iptables"]) or (not cfg["ipaddrs"]) or (not cfg["iproutes"]) or (not cfg["ipsets"]):
                print("please run 'load' cmds to load configurations.")
                continue
            Runner(cfg["ipaddrs"], cfg["non_local_ip"], cfg["iproutes"], cfg["ipsets"], cfg["iptables"]).RunIncommingPacket(cfg["packet"])
            continue
        if input.split()[0] == "run-localgen-packet":
            if (not cfg["iptables"]) or (not cfg["ipaddrs"]) or (not cfg["iproutes"]) or (not cfg["ipsets"]):
                print("please run 'load' cmds to load configurations.")
                continue
            Runner(cfg["ipaddrs"], cfg["non_local_ip"], cfg["iproutes"], cfg["ipsets"], cfg["iptables"]).RunLocalGenPacket(cfg["packet"])
            continue

    # p.set_source("192.168.199.10").set_dest("192.168.199.14").dport = 2379
    # p.iface = "cali30b5015dbf7"
    # p.set_source("192.16.1.51").set_dest("192.16.1.29").dport = 2379
    # p.set_source("192.16.1.51").set_dest("10.254.0.1").dport = 443
    # Runner(addrs, non_local_ip, routes, sets, tables).RunIncommingPacket(p)
    # answer = prompt('Give me some input: ', bottom_toolbar=bottom_statusbar)
    # print('You said: %s' % answer)
    # p.set_dest("192.16.1.51").dport = 2379
    # Runner(cfg["ipaddrs"], cfg["non_local_ip"], cfg["iproutes"], cfg["ipsets"], cfg["iptables"]).RunLocalGenPacket(p)
