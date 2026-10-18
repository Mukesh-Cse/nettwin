
"""Compare assertion detection with expanded access exposure."""

import json

from nettwin.core import load
from nettwin.mutation import benchmark
from nettwin.mutation_exposure import analyze


def main():
    scenario = load("benchmarks/guest_isolation.json")

    mutation_report = benchmark(scenario)
    exposure_report = analyze(scenario)

    detected = {
        item["name"]: item["detected"]
        for item in mutation_report["records"]
    }

    gaps = []

    for item in exposure_report["records"]:
        mutation_name = item["mutation"]

        if (
            item["newly_allowed_flows"] > 0
            and not detected.get(mutation_name, False)
        ):
            gaps.append({
                "mutation": mutation_name,
                "newly_allowed_flows": item["newly_allowed_flows"],
                "examples": item["examples"],
            })

    report = {
        "scenario": scenario.name,
        "mutants": exposure_report["mutants"],
        "analyzed_flows": exposure_report["analyzed_flows"],
        "access_expanding_mutants": (
            exposure_report["mutants_expanding_access"]
        ),
        "access_expansions_missed_by_assertions": len(gaps),
        "gaps": gaps,
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
