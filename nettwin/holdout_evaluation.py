
"""Evaluate security-test selection on held-out mutation operators."""

import json

from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates


TRAIN_OPERATORS = {
    "widen_source",
    "widen_destination",
    "flip_action",
}

TEST_OPERATORS = {
    "change_port",
    "change_protocol",
    "delete",
    "swap",
}


def evaluate(path):
    scenario = load(path)
    mutants = list(candidates(scenario))

    training = [
        (name, mutant)
        for name, mutant, metadata in mutants
        if metadata["operator"] in TRAIN_OPERATORS
    ]

    held_out = [
        (name, mutant)
        for name, mutant, metadata in mutants
        if metadata["operator"] in TEST_OPERATORS
    ]

    original_tests = [
        (a.flow, a.expected)
        for a in scenario.assertions
    ]

    ports = sorted({
        r.port for r in scenario.rules
        if isinstance(r.port, int) and r.port > 0
    })

    coverage = {}

    for src in scenario.nodes:
        for dst in scenario.nodes:
            if src == dst:
                continue

            for protocol in ("tcp", "udp"):
                for port in ports:
                    flow = Flow(
                        source=src,
                        destination=dst,
                        protocol=protocol,
                        port=port,
                    )

                    expected = decide(scenario, flow)[0]

                    # Only add tests for normally denied traffic.
                    if expected != "DENY":
                        continue

                    detected = {
                        name
                        for name, mutant in training
                        if decide(mutant, flow)[0] == "ALLOW"
                    }

                    if detected:
                        coverage[
                            (src, dst, protocol, port)
                        ] = detected

    remaining = set().union(
        *coverage.values()
    ) if coverage else set()

    selected = []

    while remaining:
        best = max(
            coverage,
            key=lambda key: len(coverage[key] & remaining),
        )

        newly_detected = coverage[best] & remaining

        if not newly_detected:
            break

        selected.append((
            Flow(
                source=best[0],
                destination=best[1],
                protocol=best[2],
                port=best[3],
            ),
            "DENY",
        ))

        remaining -= newly_detected

    expanded_tests = original_tests + selected

    def detected_count(tests):
        return sum(
            any(
                decide(mutant, flow)[0] != expected
                for flow, expected in tests
            )
            for _, mutant in held_out
        )

    original_detected = detected_count(original_tests)
    expanded_detected = detected_count(expanded_tests)

    return {
        "scenario": scenario.name,
        "training_mutants": len(training),
        "held_out_mutants": len(held_out),
        "original_assertions": len(original_tests),
        "additional_assertions": len(selected),
        "expanded_assertions": len(expanded_tests),
        "original_held_out_detected": original_detected,
        "expanded_held_out_detected": expanded_detected,
        "original_detection_rate": round(
            100 * original_detected / len(held_out), 1
        ) if held_out else None,
        "expanded_detection_rate": round(
            100 * expanded_detected / len(held_out), 1
        ) if held_out else None,
    }


if __name__ == "__main__":
    paths = [
        "benchmarks/guest_isolation.json",
        "benchmarks/enterprise_segmentation.json",
    ]

    results = [evaluate(path) for path in paths]

    print(json.dumps(results, indent=2))
