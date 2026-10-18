
"""Run 30 reproducible NetTwin probe-strategy trials."""

import csv
import json
import statistics
from pathlib import Path

from nettwin.core import from_dict
from nettwin.experiments import compare


ROOT = Path(__file__).resolve().parent
SCENARIO_PATH = ROOT / "benchmarks" / "guest_isolation.json"
OUTPUT_DIR = ROOT / "results"

SEEDS = range(30)
BUDGETS = (5, 10, 25, 50)
STRATEGIES = ("normal", "random", "guided")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with SCENARIO_PATH.open("r", encoding="utf-8") as file:
        scenario = from_dict(json.load(file))

    rows = []

    for seed in SEEDS:
        result = compare(
            scenario,
            seed=seed,
            budgets=BUDGETS,
        )

        for budget_result in result["results"]:
            budget = budget_result["budget"]

            for strategy in STRATEGIES:
                metrics = budget_result[strategy]

                rows.append({
                    "seed": seed,
                    "budget": budget,
                    "strategy": strategy,
                    "detected_faults": metrics["detected_faults"],
                    "confirmed_faults": metrics["total_confirmed_faults"],
                    "recall": metrics["fault_detection_recall"],
                    "assertion_coverage": metrics["assertion_coverage"],
                })

    trials_path = OUTPUT_DIR / "probe_trials.csv"

    with trials_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summary_rows = []

    for budget in BUDGETS:
        for strategy in STRATEGIES:
            selected = [
                row["recall"]
                for row in rows
                if row["budget"] == budget
                and row["strategy"] == strategy
                and row["recall"] is not None
            ]

            summary_rows.append({
                "budget": budget,
                "strategy": strategy,
                "mean_recall": statistics.mean(selected) if selected else None,
                "std_recall": (
                    statistics.stdev(selected)
                    if len(selected) > 1 else 0.0
                ),
                "trials": len(selected),
            })

    summary_path = OUTPUT_DIR / "probe_summary.csv"

    with summary_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=summary_rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print("\nNETTWIN EXPERIMENT RESULTS")
    print("=" * 65)

    for row in summary_rows:
        print(
            f"Budget={row['budget']:>2} | "
            f"{row['strategy']:<7} | "
            f"Mean recall={row['mean_recall']:.3f} | "
            f"Std={row['std_recall']:.3f}"
        )

    print("\nSaved:")
    print(trials_path)
    print(summary_path)


if __name__ == "__main__":
    main()
