
"""Compare probe strategies against confirmed configuration mutations."""

import random

from .core import Scenario, Flow, decide, verify
from .mutation import candidates


def flow_key(flow):
    return (
        flow.source,
        flow.destination,
        flow.protocol,
        flow.port,
    )


def compare(s: Scenario, seed=42, budgets=(5, 10, 25, 50)):
    """Evaluate normal, random, and guided testing on known faults."""

    if not verify(s)["all_passed"]:
        raise ValueError(
            "Reference scenario must satisfy all assertions"
        )

    nodes = list(s.nodes)

    # Define the same traffic universe for every strategy.
    flows = [
        Flow(a, b, proto, port)
        for a in nodes
        for b in nodes
        if a != b
        for proto, port in (
            ("tcp", 22),
            ("tcp", 80),
            ("tcp", 443),
            ("tcp", 5432),
            ("udp", 53),
        )
    ]

    required = {
        flow_key(a.flow): a.expected
        for a in s.assertions
    }

    normal = [
        a.flow for a in s.assertions
        if a.expected == "ALLOW"
    ]

    denied = [
        a.flow for a in s.assertions
        if a.expected == "DENY"
    ]

    # Generate one reproducible random ordering.
    rng = random.Random(seed)
    random_flows = flows.copy()
    rng.shuffle(random_flows)

    # Guided probes prioritize security restrictions.
    guided = denied + normal + [
        f for f in random_flows
        if flow_key(f) not in required
    ]

    # Identify faults independently of probe strategy.
    confirmed_mutants = []

    for name, mutant, metadata in candidates(s):
        changed = any(
            decide(s, assertion.flow)[0]
            != decide(mutant, assertion.flow)[0]
            for assertion in s.assertions
        )

        if changed:
            confirmed_mutants.append(
                (name, mutant, metadata)
            )

    def evaluate_strategy(probes, budget):
        selected = probes[:budget]

        detected = 0
        detected_names = []

        for name, mutant, _ in confirmed_mutants:
            found = False

            for flow in selected:
                k = flow_key(flow)

                # Compare only flows with approved expectations.
                if k not in required:
                    continue

                actual = decide(mutant, flow)[0]
                expected = required[k]

                if actual != expected:
                    found = True
                    break

            if found:
                detected += 1
                detected_names.append(name)

        total = len(confirmed_mutants)

        coverage = len({
            flow_key(f)
            for f in selected
            if flow_key(f) in required
        })

        return {
            "detected_faults": detected,
            "total_confirmed_faults": total,
            "fault_detection_recall": (
                detected / total if total else None
            ),
            "tested_assertions": coverage,
            "assertion_coverage": (
                coverage / len(required)
                if required else 0.0
            ),
            "detected_mutants": detected_names,
        }

    results = []

    for budget in budgets:
        results.append({
            "budget": budget,
            "normal": evaluate_strategy(normal, budget),
            "random": evaluate_strategy(random_flows, budget),
            "guided": evaluate_strategy(guided, budget),
        })

    return {
        "seed": seed,
        "backend": "policy-model",
        "evaluation_type": "mutation_fault_detection",
        "confirmed_faults": len(confirmed_mutants),
        "results": results,
    }
