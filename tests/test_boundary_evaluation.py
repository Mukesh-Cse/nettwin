
import unittest

from nettwin.core import Flow, decide, load
from nettwin.mutation import candidates
from nettwin.boundary_evaluation import evaluate as boundary_evaluate
from nettwin.observable_holdout import evaluate as observable_evaluate


SCENARIOS = [
    "benchmarks/guest_isolation.json",
    "benchmarks/enterprise_segmentation.json",
    "benchmarks/cloud_microservices.json",
]


class TestBoundaryEvaluation(unittest.TestCase):


    def test_individual_observable_mutants(self):
        held_out_operators = {
            "change_port",
            "change_protocol",
            "delete",
            "swap",
        }

        for path in SCENARIOS:
            with self.subTest(scenario=path):
                scenario = load(path)
                observable_report = observable_evaluate(path)

                original_tests = [
                    (assertion.flow, assertion.expected)
                    for assertion in scenario.assertions
                ]

                boundary_tests = []

                for rule in scenario.rules:
                    if (
                        rule.action != "ALLOW"
                        or rule.source not in scenario.nodes
                        or rule.destination not in scenario.nodes
                        or rule.protocol not in ("tcp", "udp")
                        or rule.port == 0
                    ):
                        continue

                    opposite_protocol = (
                        "udp" if rule.protocol == "tcp" else "tcp"
                    )
                    alternate_port = (
                        8080 if rule.port != 8080 else 8081
                    )

                    candidate_flows = [
                        Flow(
                            rule.source,
                            rule.destination,
                            opposite_protocol,
                            rule.port,
                        ),
                        Flow(
                            rule.source,
                            rule.destination,
                            rule.protocol,
                            alternate_port,
                        ),
                    ]

                    for flow in candidate_flows:
                        if decide(scenario, flow)[0] != "DENY":
                            continue

                        if any(
                            existing_flow == flow
                            for existing_flow, _ in (
                                original_tests + boundary_tests
                            )
                        ):
                            continue

                        boundary_tests.append((flow, "DENY"))

                expanded_tests = original_tests + boundary_tests

                records = {
                    record["mutation"]: record
                    for record in observable_report["records"]
                }

                checked = 0
                detected = 0

                for name, mutant, metadata in candidates(scenario):
                    if metadata["operator"] not in held_out_operators:
                        continue

                    self.assertIn(name, records)

                    if not records[name]["observable"]:
                        continue

                    checked += 1

                    caught = any(
                        decide(mutant, flow)[0] != expected
                        for flow, expected in expanded_tests
                    )

                    self.assertTrue(
                        caught,
                        f"Observable mutation not detected: "
                        f"{path} / {name}",
                    )

                    detected += 1

                self.assertEqual(
                    checked,
                    observable_report["observable_mutants"],
                )
                self.assertEqual(detected, checked)

    def test_all_scenarios(self):
        total_observable = 0
        total_detected = 0

        for path in SCENARIOS:
            with self.subTest(scenario=path):
                boundary = boundary_evaluate(path)
                observable = observable_evaluate(path)

                self.assertEqual(
                    boundary["scenario"],
                    observable["scenario"]
                )

                self.assertEqual(
                    boundary["held_out_mutants"],
                    observable["held_out_mutants"]
                )

                self.assertGreater(
                    boundary["boundary_tests"], 0
                )

                self.assertEqual(
                    boundary["expanded_tests"],
                    boundary["original_tests"]
                    + boundary["boundary_tests"]
                )

                self.assertEqual(
                    boundary["expanded_detected"],
                    observable["observable_mutants"]
                )

                self.assertGreaterEqual(
                    boundary["expanded_detected"],
                    boundary["original_detected"]
                )

                total_observable += observable["observable_mutants"]
                total_detected += boundary["expanded_detected"]

        self.assertEqual(total_observable, 39)
        self.assertEqual(total_detected, 39)


if __name__ == "__main__":
    unittest.main()
