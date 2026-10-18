
"""Evaluate mutation-independent boundary tests around ALLOW rules."""

import json

from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates


HELD_OUT = {
    "change_port",
    "change_protocol",
    "delete",
    "swap",
}

def generate_boundary_tests(scenario):
    """Generate negative security tests around allowed flows."""
    original = [
        (a.flow, a.expected)
        for a in scenario.assertions
    ]

    added = []

    for rule in scenario.rules:
        if rule.action != "ALLOW":
            continue

        if rule.source not in scenario.nodes:
            continue

        if rule.destination not in scenario.nodes:
            continue

        if rule.protocol not in ("tcp", "udp"):
            continue

        if rule.port == 0:
            continue

        alternate_protocol = (
            "udp" if rule.protocol == "tcp" else "tcp"
        )

        alternate_port = (
            8080 if rule.port != 8080 else 8081
        )

        boundary_flows = [
            Flow(
                rule.source,
                rule.destination,
                alternate_protocol,
                rule.port,
            ),
            Flow(
                rule.source,
                rule.destination,
                rule.protocol,
                alternate_port,
            ),
        ]

        for flow in boundary_flows:
            expected = decide(scenario, flow)[0]

            if expected != "DENY":
                continue

            if any(
                existing == flow
                for existing, _ in original + added
            ):
                continue

            added.append((flow, expected))

    return added

def evaluate(path):
    scenario = load(path)

    original = [
        (a.flow, a.expected)
        for a in scenario.assertions
    ]

    added = generate_boundary_tests(scenario)

    expanded = original + added

    held_out = [
        (name, mutant)
        for name, mutant, metadata in candidates(scenario)
        if metadata["operator"] in HELD_OUT
    ]

    def detected(tests, mutant):
        return any(
            decide(mutant, flow)[0] != expected
            for flow, expected in tests
        )

    original_count = sum(
        detected(original, mutant)
        for _, mutant in held_out
    )

    expanded_count = sum(
        detected(expanded, mutant)
        for _, mutant in held_out
    )

    return {
        "scenario": scenario.name,
        "held_out_mutants": len(held_out),
        "original_tests": len(original),
        "boundary_tests": len(added),
        "expanded_tests": len(expanded),
        "original_detected": original_count,
        "expanded_detected": expanded_count,
        "original_rate": round(
            100 * original_count / len(held_out), 1
        ),
        "expanded_rate": round(
            100 * expanded_count / len(held_out), 1
        ),
    }


if __name__ == "__main__":
    results = [
        evaluate("benchmarks/guest_isolation.json"),
        evaluate("benchmarks/enterprise_segmentation.json"),
    ]

    print(json.dumps(results, indent=2))
