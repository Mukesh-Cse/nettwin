
"""Plan real packet tests from NetTwin policy assertions.

This module creates a test plan only.
It does not configure firewalls or send packets.
"""

import json
from dataclasses import asdict
from pathlib import Path

from nettwin.core import decide, load


def build_packet_test_plan(scenario):
    """Translate policy assertions into packet test specifications."""

    tests = []

    for assertion in scenario.assertions:
        flow = assertion.flow

        model_action, matched_rule = decide(
            scenario,
            flow,
        )

        if flow.protocol == "tcp":
            support = "PLANNED_TCP"
        elif flow.protocol == "udp":
            support = "PLANNED_UDP"
        else:
            support = "UNSUPPORTED"

        tests.append({
            "assertion_id": assertion.id,
            "source": flow.source,
            "source_ip": scenario.nodes[flow.source],
            "destination": flow.destination,
            "destination_ip": scenario.nodes[flow.destination],
            "protocol": flow.protocol,
            "port": flow.port,
            "expected": assertion.expected,
            "model_action": model_action,
            "matched_rule": matched_rule,
            "model_matches_expected": (
                model_action == assertion.expected
            ),
            "execution_status": support,
            "packet_executed": False,
        })

    return {
        "scenario": scenario.name,
        "backend": "policy-packet-planner",
        "total_assertions": len(tests),
        "tcp_tests_planned": sum(
            t["execution_status"] == "PLANNED_TCP"
            for t in tests
        ),
        "udp_tests_planned": sum(
            t["execution_status"] == "PLANNED_UDP"
            for t in tests
        ),
        "packet_tests_executed": 0,
        "tests": tests,
    }


def main():
    project_root = Path(__file__).resolve().parent.parent

    scenario_path = (
        project_root
        / "benchmarks"
        / "guest_isolation.json"
    )

    scenario = load(str(scenario_path))

    report = build_packet_test_plan(scenario)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
