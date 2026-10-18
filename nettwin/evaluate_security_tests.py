
"""Evaluate original and expanded security test suites."""

import json

from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates
from nettwin.security_test_selection import select_security_tests


def evaluate():
    scenario = load("benchmarks/guest_isolation.json")
    selection = select_security_tests(scenario)

    original_tests = [
        (assertion.flow, assertion.expected)
        for assertion in scenario.assertions
    ]

    additional_tests = [
        (
            Flow(
                source=test["source"],
                destination=test["destination"],
                protocol=test["protocol"],
                port=test["port"],
            ),
            test["expected"],
        )
        for test in selection["selected_tests"]
    ]

    expanded_tests = original_tests + additional_tests

    # Ensure the unmodified scenario passes the expanded suite.
    for flow, expected in expanded_tests:
        actual = decide(scenario, flow)[0]
        if actual != expected:
            raise RuntimeError(
                f"Baseline failed: {flow}, "
                f"expected={expected}, actual={actual}"
            )

    records = []

    for name, mutant, metadata in candidates(scenario):
        original_detected = any(
            decide(mutant, flow)[0] != expected
            for flow, expected in original_tests
        )

        expanded_detected = any(
            decide(mutant, flow)[0] != expected
            for flow, expected in expanded_tests
        )

        newly_allowed = any(
            decide(scenario, flow)[0] == "DENY"
            and decide(mutant, flow)[0] == "ALLOW"
            for flow, _ in expanded_tests
        )

        records.append({
            "mutation": name,
            **metadata,
            "original_detected": original_detected,
            "expanded_detected": expanded_detected,
            "newly_allowed_on_tested_flows": newly_allowed,
        })

    access_expanding = [
        record
        for record in records
        if record["newly_allowed_on_tested_flows"]
    ]

    return {
        "original_assertions": len(original_tests),
        "expanded_assertions": len(expanded_tests),
        "mutants": len(records),
        "original_detected": sum(
            record["original_detected"] for record in records
        ),
        "expanded_detected": sum(
            record["expanded_detected"] for record in records
        ),
        "access_expanding_mutants": len(access_expanding),
        "access_expansions_detected": sum(
            record["expanded_detected"]
            for record in access_expanding
        ),
        "records": records,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
