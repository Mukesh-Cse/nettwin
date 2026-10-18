"""Real firewall validation of NetTwin boundary security tests."""

import json
import os
import sys

from nettwin.core import load, decide
from nettwin.boundary_evaluation import generate_boundary_tests

from nettwin.policy_multi_tcp_test import (
    create_topology,
    configure_firewall,
    start_server,
    start_udp_server,
    probe,
    probe_udp,
    get_firewall_counters,
    cleanup,
)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo.")

    scenario = load("benchmarks/guest_isolation.json")

    original = [
        (a.flow, a.expected)
        for a in scenario.assertions
    ]

    boundary = generate_boundary_tests(scenario)

    tests = original + boundary

    print(f"Scenario: {scenario.name}")
    print(f"Original tests: {len(original)}")
    print(f"Boundary tests: {len(boundary)}")
    print(f"Total tests: {len(tests)}")
    created = []
    servers = []

    try:
        print("\nCreating isolated network topology...")
        create_topology(scenario, created)

        print("Topology created successfully.")
        print(f"Namespaces created: {len(created)}")
        print("\nInstalling nftables firewall rules...")
        configure_firewall(scenario)

        counters = get_firewall_counters()

        print("Firewall configured successfully.")
        print(f"Firewall counter entries: {len(counters)}")

        expected_entries = len(scenario.rules) + 2

        if len(counters) != expected_entries:
            raise RuntimeError(
                "Firewall rule count does not match the policy."
            )

        print("Firewall rule count verified.")
        print("\nStarting TCP and UDP test servers...")

        listeners = sorted({
            (
                flow.destination,
                scenario.nodes[flow.destination],
                flow.port,
                flow.protocol,
            )
            for flow, expected in tests
            if flow.protocol in ("tcp", "udp")
        })

        for node, address, port, protocol in listeners:
            if protocol == "tcp":
                process = start_server(node, address, port)
            else:
                process = start_udp_server(node, address, port)

            servers.append(process)

            print(
                f"Started {protocol.upper()} server: "
                f"{node}:{port}"
            )

        print(f"Total test servers started: {len(servers)}")

        print("\nRunning all real firewall security tests...")

        results = []
        rule_ids = (
            ["CONNECTION_TRACKING"]
            + [rule.id for rule in scenario.rules]
            + ["DEFAULT"]
        )

        for index, (flow, expected) in enumerate(tests, 1):
            source_ip = scenario.nodes[flow.source]
            destination_ip = scenario.nodes[flow.destination]

            model_action, matched_rule = decide(scenario, flow)

            counters_before = get_firewall_counters()

            if flow.protocol == "tcp":
                observed_probe = probe(
                    flow.source, source_ip, destination_ip, flow.port
                )
            elif flow.protocol == "udp":
                observed_probe = probe_udp(
                    flow.source, source_ip, destination_ip, flow.port
                )
            else:
                raise RuntimeError(
                    f"Unsupported protocol: {flow.protocol}"
                )

            counters_after = get_firewall_counters()

            if (
                len(counters_before) != len(rule_ids)
                or len(counters_after) != len(rule_ids)
            ):
                raise RuntimeError("Firewall counter count mismatch.")

            counter_changes = {
                rule_id: after["packets"] - before["packets"]
                for rule_id, before, after in zip(
                    rule_ids, counters_before, counters_after
                )
            }

            observed = (
                "ALLOW" if observed_probe["allowed"] else "DENY"
            )

            matched_packets = counter_changes.get(matched_rule, 0)

            passed = (
                model_action == expected
                and observed == expected
                and matched_packets > 0
            )

            results.append({
                "test_id": index,
                "category": (
                    "original" if index <= len(original) else "boundary"
                ),
                "source": flow.source,
                "destination": flow.destination,
                "protocol": flow.protocol,
                "port": flow.port,
                "expected": expected,
                "observed": observed,
                "matched_rule": matched_rule,
                "matched_rule_packets": matched_packets,
                "passed": passed,
            })

            status = "PASS" if passed else "FAIL"
            print(
                f"[{index:02d}/{len(tests)}] {status} | "
                f"{flow.source} -> {flow.destination} | "
                f"{flow.protocol.upper()}/{flow.port} | "
                f"Expected: {expected} | Observed: {observed} | "
                f"Rule: {matched_rule} | Packets: {matched_packets}"
            )

        passed_count = sum(item["passed"] for item in results)

        print("\nValidation summary")
        print(f"Total tests: {len(results)}")
        print(f"Passed: {passed_count}")
        print(f"Failed: {len(results) - passed_count}")
        os.makedirs("results", exist_ok=True)

        report = {
            "scenario": scenario.name,
            "execution_mode": "real_linux_nftables",
            "original_tests": len(original),
            "boundary_tests": len(boundary),
            "total_tests": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "tests": results,
        }

        report_path = "results/real_boundary_validation_results.json"

        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)

        print(f"JSON report saved: {report_path}")

        if passed_count != len(results):
            raise RuntimeError("Real firewall validation failed.")

        print("All real firewall security tests PASSED.")


    finally:
        print("\nCleaning up network namespaces...")
        cleanup(created, servers)
        print("Cleanup completed.")

if __name__ == "__main__":
    main()
