
"""Analyze mutation effects beyond the original assertions."""

import json

from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates


def analyze(scenario):
    protocols = ("tcp", "udp")
    ports = sorted({
        rule.port
        for rule in scenario.rules
        if isinstance(rule.port, int) and rule.port > 0
    })

    flows = [
        Flow(
            source=source,
            destination=destination,
            protocol=protocol,
            port=port,
        )
        for source in scenario.nodes
        for destination in scenario.nodes
        if source != destination
        for protocol in protocols
        for port in ports
    ]

    records = []

    for name, mutant, metadata in candidates(scenario):
        changed_flows = []
        new_allows = []

        for flow in flows:
            original_action = decide(scenario, flow)[0]
            mutant_action = decide(mutant, flow)[0]

            if original_action != mutant_action:
                entry = {
                    "source": flow.source,
                    "destination": flow.destination,
                    "protocol": flow.protocol,
                    "port": flow.port,
                    "original": original_action,
                    "mutated": mutant_action,
                }

                changed_flows.append(entry)

                if (
                    original_action == "DENY"
                    and mutant_action == "ALLOW"
                ):
                    new_allows.append(entry)

        records.append({
            "mutation": name,
            **metadata,
            "changed_flows": len(changed_flows),
            "newly_allowed_flows": len(new_allows),
            "examples": new_allows[:3],
        })

    return {
        "scenario": scenario.name,
        "analyzed_flows": len(flows),
        "mutants": len(records),
        "mutants_changing_flows": sum(
            r["changed_flows"] > 0 for r in records
        ),
        "mutants_expanding_access": sum(
            r["newly_allowed_flows"] > 0 for r in records
        ),
        "records": records,
    }


if __name__ == "__main__":
    scenario = load("benchmarks/guest_isolation.json")
    print(json.dumps(analyze(scenario), indent=2))
