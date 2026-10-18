
"""Select additional security tests to detect access-expanding mutants."""

import json
from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates


def select_security_tests(scenario):
    ports = sorted({
        rule.port
        for rule in scenario.rules
        if isinstance(rule.port, int) and rule.port > 0
    })

    flows = [
        Flow(
            source=src,
            destination=dst,
            protocol=proto,
            port=port,
        )
        for src in scenario.nodes
        for dst in scenario.nodes
        if src != dst
        for proto in ("tcp", "udp")
        for port in ports
    ]

    existing = {
        (
            a.flow.source,
            a.flow.destination,
            a.flow.protocol,
            a.flow.port,
        )
        for a in scenario.assertions
    }

    mutations = list(candidates(scenario))
    mutant_coverage = {}

    for flow in flows:
        key = (
            flow.source,
            flow.destination,
            flow.protocol,
            flow.port,
        )

        if key in existing:
            continue

        original = decide(scenario, flow)[0]

        if original != "DENY":
            continue

        detected = set()

        for name, mutant, _ in mutations:
            if decide(mutant, flow)[0] == "ALLOW":
                detected.add(name)

        if detected:
            mutant_coverage[key] = detected

    remaining = set().union(
        *mutant_coverage.values()
    ) if mutant_coverage else set()

    selected = []

    while remaining:
        best_flow = max(
            mutant_coverage,
            key=lambda key: len(
                mutant_coverage[key] & remaining
            ),
        )

        newly_detected = mutant_coverage[best_flow] & remaining

        if not newly_detected:
            break

        selected.append({
            "source": best_flow[0],
            "destination": best_flow[1],
            "protocol": best_flow[2],
            "port": best_flow[3],
            "expected": "DENY",
            "new_mutants_detected": len(newly_detected),
            "mutations": sorted(newly_detected),
        })

        remaining -= newly_detected

    covered = set().union(
        *(set(item["mutations"]) for item in selected)
    ) if selected else set()

    return {
        "scenario": scenario.name,
        "candidate_flows": len(flows),
        "additional_tests": len(selected),
        "access_expanding_mutants_covered": len(covered),
        "uncovered_mutants": sorted(remaining),
        "selected_tests": selected,
    }


if __name__ == "__main__":
    scenario = load("benchmarks/guest_isolation.json")
    print(json.dumps(select_security_tests(scenario), indent=2))
