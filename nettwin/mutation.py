"""Mutation benchmark with confirmed and equivalent mutants."""
from dataclasses import replace
from .core import Scenario, Rule, verify, decide

def candidates(s: Scenario):
    for i,r in enumerate(s.rules):
        for operator, changed in [
            ("flip_action",replace(r,action="ALLOW" if r.action=="DENY" else "DENY")),
            ("widen_source",replace(r,source="any")),
            ("widen_destination",replace(r,destination="any")),
            ("change_port",replace(r,port=0 if r.port else 443)),
            ("change_protocol",replace(r,protocol="any" if r.protocol!="any" else "tcp")),
        ]:
            rules=s.rules.copy();rules[i]=changed
            yield f"{operator}:{r.id}",replace(s,rules=rules),{"operator":operator,"rule_id":r.id}
        rules=s.rules.copy();rules.pop(i)
        yield f"delete:{r.id}",replace(s,rules=rules),{"operator":"delete","rule_id":r.id}
        if i+1 < len(s.rules):
            rules=s.rules.copy();rules[i],rules[i+1]=rules[i+1],rules[i]
            yield f"swap:{r.id}",replace(s,rules=rules),{"operator":"swap","rule_id":r.id}

def benchmark(s: Scenario) -> dict:
    baseline=verify(s)
    if not baseline['all_passed']: raise ValueError('Reference scenario must satisfy all assertions')
    records=[]
    for name,mutant,metadata in candidates(s):
        result=verify(mutant)
        changed=any(decide(s,a.flow)[0]!=decide(mutant,a.flow)[0] for a in s.assertions)
        records.append({"name":name,**metadata,"confirmed_fault_on_assertions":changed,
                        "detected":not result['all_passed'],"failures":result['total']-result['passed']})
    confirmed=[r for r in records if r['confirmed_fault_on_assertions']]
    return {"scenario":s.name,"backend":"policy-model","mutants":len(records),
            "confirmed_faults":len(confirmed),"equivalent_on_assertions":len(records)-len(confirmed),
            "detected_confirmed":sum(r['detected'] for r in confirmed),
            "recall_on_assertions":sum(r['detected'] for r in confirmed)/len(confirmed) if confirmed else None,
            "records":records}
