"""Counterfactual rule deletion and bounded repairs."""
from dataclasses import replace
from .core import Scenario, verify, Rule

def diagnose(s: Scenario) -> dict:
    before=verify(s)
    if before['all_passed']: return {"failures":[],"candidates":[]}
    failures=[x for x in before['results'] if not x['passed']]
    candidates=[]
    for i,r in enumerate(s.rules):
        variant=replace(s,rules=s.rules[:i]+s.rules[i+1:])
        after=verify(variant)
        fixed=sum(1 for b,a in zip(before['results'],after['results']) if not b['passed'] and a['passed'])
        regressions=sum(1 for b,a in zip(before['results'],after['results']) if b['passed'] and not a['passed'])
        if fixed: candidates.append({"rule_id":r.id,"operation":"delete","fixed":fixed,"regressions":regressions})
    candidates.sort(key=lambda x:(-x['fixed'],x['regressions'],x['rule_id']))
    return {"failures":failures,"candidates":candidates}

def repair(s: Scenario) -> dict:
    """Conservative bounded single-edit search. No unsafe automatic deployment."""
    before=verify(s)
    if before['all_passed']: return {"success":True,"change":"none","scenario":s}
    variants=[]
    for i,r in enumerate(s.rules):
        variants.append((f"delete:{r.id}",replace(s,rules=s.rules[:i]+s.rules[i+1:])))
        rules=s.rules.copy();rules[i]=replace(r,action="ALLOW" if r.action=="DENY" else "DENY")
        variants.append((f"flip:{r.id}",replace(s,rules=rules)))
    for a in s.assertions:
        rule=Rule(id=f"repair_{a.id}",source=a.flow.source,destination=a.flow.destination,
                  protocol=a.flow.protocol,port=a.flow.port,action=a.expected)
        variants.append((f"prepend:{a.id}",replace(s,rules=[rule]+s.rules)))
    for change,v in variants:
        if verify(v)['all_passed']:
            return {"success":True,"change":change,"scenario":v}
    return {"success":False,"change":None,"scenario":s}
