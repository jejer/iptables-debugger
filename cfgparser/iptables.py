import re
import ipaddress

from cfgparser.rule import Rule
from cfgparser.matches.match import NewMatch
from cfgparser.targets.target import NewTarget, NewGoto

# iptables: {table: {chain: {policy, rules[]}}}
def ParseIPTables(filename):
    current_table = ""
    iptables = {}

    with open(filename, "r") as file:
        for line in file:
            isTable, table = parseTable(iptables, line)
            if isTable:
                current_table = table
                continue
            if parseChain(iptables, current_table, line):
                continue
            if parseRule(iptables, current_table, line):
                continue

    return iptables

def parseTable(iptables, line):
    tablere = re.compile(r"^\*(?P<tablename>\S+)$")
    m = tablere.match(line)
    if not m:
        return False, ""
    iptables.update({m.group("tablename"): {}})
    return True, m.group("tablename")

def parseChain(iptables, table, line):
    chainre = re.compile(r"^:(?P<chainname>\S+) (?P<policy>\S+) .*$")
    m = chainre.match(line)
    if not m:
        return False
    iptables[table].update({m.group("chainname"): {"policy": m.group("policy"), "rules": []}})
    return True

def parseRule(iptables, table, line):
    rulere = re.compile(r"^-A (?P<chainname>\S+) (?P<rule>.+)$")
    m = rulere.match(line)
    if not m:
        return False

    rule = Rule(line)
    # print(line)
    for block in parseRuleBlock(m.group("rule")):
        if block["type"] == "i":
            rule.iface = block["value"]
            rule.invert_iface = block["invert"]

        if block["type"] == "o":
            rule.oface = block["value"]
            rule.invert_oface = block["invert"]

        if block["type"] == "s":
            rule.source = ipaddress.ip_network(block["value"])
            rule.invert_source = block["invert"]

        if block["type"] == "d":
            rule.dest = ipaddress.ip_network(block["value"])
            rule.invert_dest = block["invert"]

        if block["type"] == "p":
            rule.protocol = block["value"]
            rule.invert_protocol = block["invert"]

        if block["type"] == "m":
            match = NewMatch(block["value"], block["raw"])
            if match:
                rule.matches.append(match)

        if block["type"] == "j":
            rule.target = NewTarget(block["value"], block["raw"])

        if block["type"] == "g":
            rule.target = NewGoto(block["value"], block["raw"])

    iptables[table][m.group("chainname")]["rules"].append(rule)
    return True

def parseRuleBlock(rule):
    blkre = re.compile('^-[a-z] | -[a-z] ')
    blks = list(blkre.finditer(rule))
    blocks = []
    for i in range(len(blks)):
        head = blks[i].start()
        if head != 0:
            head += 1
        tail = len(rule)
        if i+1 != len(blks):
            tail = blks[i+1].start()
        
        raw = rule[head:tail]
        block = {"raw": raw, "type": rule[head+1], "value": raw.split()[1], "invert": False}
        if head > 1 and rule[head-2] == "!":
            block["invert"] = True
        blocks.append(block)
    return blocks
