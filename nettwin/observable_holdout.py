
"""Classify held-out mutations by observable network behavior."""

import json

from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates

HELD_OUT_OPERATORS = {
    "change_port",
    "change_protocol",
    "delete",
    "swap",
}


def evaluate(path):
    scenario = load(path)

    ports = sorted({
        r.port
        for r in scenario.rules
        if isinstance(r.port, int) and r.port > 0
    })

    # Add representative ports beyond the configured rules.
    ports = sorted(set(ports) | {22, 53, 80, 443, 8080, 9090, 5432})

    flows = [
        Flow(src, dst, protocol, port)
        for src in scenario.nodes
        for dst in scenario.nodes
        if src != dst
        for protocol in ("tcp", "udp")
        for port in ports
    ]

    original_tests = [
        (a.flow, a.expected)
        for a in scenario.assertions
    ]

    records = []

    for name, mutant, metadata in candidates(scenario):
        if metadata["operator"] not in HELD_OUT_OPERATORS:
            continue

        changed_flows = sum(
            decide(scenario, flow)[0]
            != decide(mutant, flow)[0]
            for flow in flows
        )

        detected = any(
            decide(mutant, flow)[0] != expected
            for flow, expected in original_tests
        )

        records.append({
            "mutation": name,
            "operator": metadata["operator"],
            "observable": changed_flows > 0,
            "changed_flows": changed_flows,
            "original_detected": detected,
        })

    observable = [
        r for r in records if r["observable"]
    ]

    detected_observable = sum(
        r["original_detected"] for r in observable
    )

    return {
        "scenario": scenario.name,
        "analyzed_flows": len(flows),
        "held_out_mutants": len(records),
        "observable_mutants": len(observable),
        "equivalent_within_flow_space": (
            len(records) - len(observable)
        ),
        "detected_observable": detected_observable,
        "observable_detection_rate": round(
            100 * detected_observable / len(observable), 1
        ) if observable else None,
        "records": records,
    }


if __name__ == "__main__":
    reports = [
        evaluate("benchmarks/guest_isolation.json"),
        evaluate("benchmarks/enterprise_segmentation.json"),
    ]

    print(json.dumps(reports, indent=2))
