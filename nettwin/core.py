"""Deterministic, auditable policy model. Not a packet-level network emulator."""
from __future__ import annotations
from dataclasses import dataclass, asdict, replace
from ipaddress import ip_address, ip_network
from typing import Any
import json

@dataclass(frozen=True)
class Rule:
    id: str
    source: str
    destination: str
    protocol: str = "any"
    port: int = 0
    action: str = "DENY"

@dataclass(frozen=True)
class Flow:
    source: str
    destination: str
    protocol: str
    port: int

@dataclass(frozen=True)
class Assertion:
    id: str
    flow: Flow
    expected: str

@dataclass
class Scenario:
    name: str
    nodes: dict[str,str]
    rules: list[Rule]
    assertions: list[Assertion]
    default_action: str = "DENY"

def _valid_action(value: str) -> bool:
    return value in ("ALLOW", "DENY")

def validate(s: Scenario) -> None:
    if not _valid_action(s.default_action): raise ValueError("Invalid default action")
    if not s.nodes: raise ValueError("No nodes")
    for name, addr in s.nodes.items():
        if not name or not isinstance(addr,str): raise ValueError("Invalid node")
        ip_address(addr)
    if len({r.id for r in s.rules}) != len(s.rules): raise ValueError("Duplicate rule ID")
    if len({a.id for a in s.assertions}) != len(s.assertions): raise ValueError("Duplicate assertion ID")
    for r in s.rules:
        if not _valid_action(r.action) or r.protocol not in ("tcp","udp","icmp","any") or not 0 <= r.port <= 65535:
            raise ValueError(f"Invalid rule: {r.id}")
        for endpoint in (r.source,r.destination):
            if endpoint != "any" and endpoint not in s.nodes: ip_network(endpoint, strict=False)
    for a in s.assertions:
        if not _valid_action(a.expected): raise ValueError(f"Invalid assertion: {a.id}")
        if a.flow.source not in s.nodes or a.flow.destination not in s.nodes: raise ValueError("Unknown node")
        if a.flow.protocol not in ("tcp","udp","icmp") or not 0 <= a.flow.port <= 65535: raise ValueError("Invalid flow")

def _endpoint_match(spec: str, node: str, nodes: dict[str,str]) -> bool:
    if spec == "any": return True
    if spec in nodes: return spec == node
    return ip_address(nodes[node]) in ip_network(spec, strict=False)

def decide(s: Scenario, flow: Flow) -> tuple[str,str]:
    """Ordered first-match rules. This is a deliberately restricted ACL semantics."""
    for r in s.rules:
        if (_endpoint_match(r.source,flow.source,s.nodes)
            and _endpoint_match(r.destination,flow.destination,s.nodes)
            and r.protocol in ("any",flow.protocol)
            and (r.port == 0 or r.port == flow.port)):
            return r.action, r.id
    return s.default_action, "DEFAULT"

def verify(s: Scenario) -> dict[str,Any]:
    validate(s)
    results=[]
    for a in s.assertions:
        actual,rule=decide(s,a.flow)
        results.append({"id":a.id,"flow":asdict(a.flow),"expected":a.expected,"observed":actual,
                        "matched_rule":rule,"passed":actual==a.expected})
    return {"scenario":s.name,"backend":"policy-model","total":len(results),
            "passed":sum(x["passed"] for x in results),"results":results,
            "all_passed":all(x["passed"] for x in results)}

def from_dict(d: dict) -> Scenario:
    s=Scenario(name=d['name'],nodes=d['nodes'],rules=[Rule(**r) for r in d['rules']],
        assertions=[Assertion(id=a['id'],flow=Flow(**a['flow']),expected=a['expected']) for a in d['assertions']],
        default_action=d.get('default_action','DENY'))
    validate(s);return s

def to_dict(s: Scenario) -> dict:
    return {"name":s.name,"nodes":s.nodes,"rules":[asdict(r) for r in s.rules],
            "assertions":[asdict(a) for a in s.assertions],"default_action":s.default_action}

def load(path: str) -> Scenario:
    with open(path,encoding='utf8') as f: return from_dict(json.load(f))
