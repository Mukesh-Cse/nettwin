import pandas as pd
import json
import subprocess
from pathlib import Path

import streamlit as st
from nettwin.core import from_dict, to_dict, verify
from nettwin.mutation import benchmark
from nettwin.diagnosis import diagnose, repair
from nettwin.experiments import compare


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="NetTwin",
    layout="wide",
    page_icon="🌐",
)

st.title("NetTwin | Adversarial Network Verification")

st.caption(
    "Policy-model verification and real Linux network testing "
    "using namespaces and nftables."
)


# ============================================================
# POLICY MODEL VERIFICATION
# ============================================================

example = (
    Path(__file__).parent
    / "benchmarks"
    / "guest_isolation.json"
)

if "scenario" not in st.session_state:
    st.session_state.scenario = example.read_text(
        encoding="utf-8"
    )

raw = st.text_area(
    "Edit scenario JSON",
    height=340,
    key="scenario",
)

try:
    s = from_dict(json.loads(raw))
except Exception as exc:
    st.error(f"Invalid scenario: {exc}")
    st.stop()

result = verify(s)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Policy assertions", result["total"])
col2.metric("Passing", result["passed"])
col3.metric(
    "Violations",
    result["total"] - result["passed"],
)
col4.metric("Rules", len(s.rules))


# ============================================================
# VERIFICATION RESULTS
# ============================================================

st.subheader("Verification Results")

verification_rows = [
    {
        "Assertion": r["id"],
        "From": r["flow"]["source"],
        "To": r["flow"]["destination"],
        "Protocol": r["flow"]["protocol"],
        "Port": r["flow"]["port"],
        "Expected": r["expected"],
        "Observed": r["observed"],
        "Matched rule": r["matched_rule"],
        "Pass": r["passed"],
    }
    for r in result["results"]
]

st.dataframe(
    verification_rows,
    width="stretch",
)


# ============================================================
# MUTATION BENCHMARK AND DIAGNOSIS
# ============================================================

left, right = st.columns(2)

with left:
    st.subheader("Mutation Benchmark")

    if st.button("Run mutation benchmark"):
        b = benchmark(s) if result["all_passed"] else None

        if b is None:
            st.warning(
                "Reference scenario must pass all assertions."
            )
        else:
            st.json({
                k: v
                for k, v in b.items()
                if k != "records"
            })

            st.dataframe(
                b["records"],
                width="stretch",
            )

with right:
    st.subheader("Counterfactual Diagnosis")

    if st.button("Diagnose failures"):
        st.json(diagnose(s))

    if st.button("Propose bounded repair"):
        r = repair(s)

        st.write(
            "Success:",
            r["success"],
            "Change:",
            r["change"],
        )

        if r["success"] and r["change"] != "none":
            st.code(
                json.dumps(
                    to_dict(r["scenario"]),
                    indent=2,
                ),
                language="json",
            )


# ============================================================
# TEST SELECTION EXPERIMENT
# ============================================================

st.subheader("Test Selection Experiment")

if st.button("Compare probe strategies"):
    st.json(compare(s))


# ============================================================
# DOWNLOAD POLICY VERIFICATION REPORT
# ============================================================

st.download_button(
    label="Download verification report",
    data=json.dumps(result, indent=2),
    file_name="verification_report.json",
    mime="application/json",
)


# ============================================================
# REAL ICMP NETWORK VERIFICATION
# ============================================================

st.divider()

st.subheader("Real Network Verification")

st.caption(
    "ICMP packet verification using Linux network namespaces "
    "and nftables. Run tests live or view saved results."
)

real_report_path = (
    Path(__file__).parent
    / "results"
    / "real_packet_results.json"
)

if st.button(
    "Run Real Network Tests",
    type="primary",
):
    with st.spinner(
        "Running real packet tests in WSL Ubuntu..."
    ):
        try:
            completed = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "-u",
                    "root",
                    "--",
                    "python3",
                    "/home/gmuke/nettwin_packet_test.py",
                ],
                capture_output=True,
                text=True,
                timeout=45,
                check=True,
            )

            live_report = json.loads(completed.stdout)

            if not isinstance(live_report, dict):
                raise ValueError(
                    "Verifier returned an invalid report."
                )

            if (
                live_report.get("backend")
                != "linux-netns-nftables"
                or not isinstance(
                    live_report.get("results"),
                    list,
                )
            ):
                raise ValueError(
                    "Unexpected verifier report structure."
                )

            real_report_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            real_report_path.write_text(
                json.dumps(
                    live_report,
                    indent=2,
                ),
                encoding="utf-8",
            )

            if (
                live_report.get("passed")
                == live_report.get("total")
            ):
                st.success(
                    "All real network tests passed!"
                )
            else:
                st.warning(
                    "Some real network tests failed."
                )

        except subprocess.TimeoutExpired:
            st.error(
                "The WSL verification command timed out."
            )

        except subprocess.CalledProcessError as exc:
            st.error(
                "Real network verification failed. "
                "Check the Linux network configuration."
            )

            st.code(
                exc.stderr
                or exc.stdout
                or str(exc)
            )

        except (
            OSError,
            ValueError,
            TypeError,
        ) as exc:
            st.error(
                f"Could not execute real network tests: {exc}"
            )


# ============================================================
# DISPLAY REAL ICMP RESULTS
# ============================================================

if real_report_path.exists():
    try:
        real_report = json.loads(
            real_report_path.read_text(
                encoding="utf-8"
            )
        )

        total = real_report["total"]
        passed = real_report["passed"]

        col1, col2, col3 = st.columns(3)

        col1.metric("Real network tests", total)
        col2.metric("Passed", passed)
        col3.metric("Failed", total - passed)

        rows = []

        for item in real_report["results"]:
            probe = item["probe"]

            rows.append({
                "Test": item["test"],
                "Expected": (
                    "ALLOW"
                    if item["expected_allowed"]
                    else "DENY"
                ),
                "Observed": (
                    "ALLOW"
                    if item["observed_allowed"]
                    else "DENY"
                ),
                "Passed": item["passed"],
                "Exit code": probe["exit_code"],
            })

        st.dataframe(
            rows,
            width="stretch",
        )

        with st.expander(
            "View complete real packet test report"
        ):
            st.json(real_report)

        st.download_button(
            label="Download real network report",
            data=json.dumps(
                real_report,
                indent=2,
            ),
            file_name="real_packet_results.json",
            mime="application/json",
        )

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        st.error(
            f"Could not load real network results: {exc}"
        )

else:
    st.info(
        "No real network report found. "
        "Run the Linux packet verifier first."
    )


# ============================================================
# REAL TCP FIREWALL VERIFICATION
# ============================================================

st.divider()

st.subheader("Real TCP Firewall Verification")

st.caption(
    "TCP port 8080 verification using Linux network namespaces, "
    "nftables, and firewall packet counters."
)

tcp_report_path = (
    Path(__file__).parent
    / "results"
    / "real_tcp_results.json"
)


# ============================================================
# RUN TCP NETWORK TESTS
# ============================================================

if st.button("Run TCP Network Tests"):
    with st.spinner(
        "Running TCP firewall experiments in WSL..."
    ):
        try:
            completed = subprocess.run(
                [
                    "wsl.exe",
                    "-d",
                    "Ubuntu",
                    "-u",
                    "root",
                    "--",
                    "python3",
                    "/home/gmuke/nettwin_tcp_test.py",
                ],
                capture_output=True,
                text=True,
                timeout=45,
                check=True,
            )

            live_tcp_report = json.loads(
                completed.stdout
            )

            if not isinstance(
                live_tcp_report,
                dict,
            ):
                raise ValueError(
                    "TCP verifier returned an invalid report."
                )

            if (
                live_tcp_report.get("backend")
                != "linux-netns-nftables-tcp"
                or not isinstance(
                    live_tcp_report.get("results"),
                    list,
                )
            ):
                raise ValueError(
                    "Unexpected TCP verifier report."
                )

            tcp_report_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            tcp_report_path.write_text(
                json.dumps(
                    live_tcp_report,
                    indent=2,
                ),
                encoding="utf-8",
            )

            if (
                live_tcp_report["passed"]
                == live_tcp_report["total"]
            ):
                st.success(
                    "All TCP network tests passed!"
                )
            else:
                st.warning(
                    "Some TCP network tests failed."
                )

        except subprocess.TimeoutExpired:
            st.error(
                "TCP verification timed out."
            )

        except subprocess.CalledProcessError as exc:
            st.error(
                "TCP verification could not complete."
            )

            st.code(
                exc.stderr
                or exc.stdout
                or str(exc)
            )

        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:
            st.error(
                f"TCP verification error: {exc}"
            )


# ============================================================
# DISPLAY TCP VERIFICATION RESULTS
# ============================================================

if tcp_report_path.exists():
    try:
        tcp_report = json.loads(
            tcp_report_path.read_text(
                encoding="utf-8"
            )
        )

        # TCP test metrics
        c1, c2, c3 = st.columns(3)

        c1.metric(
            "TCP tests",
            tcp_report["total"],
        )

        c2.metric(
            "Passed",
            tcp_report["passed"],
        )

        c3.metric(
            "Failed",
            tcp_report["total"] - tcp_report["passed"],
        )

        # Firewall packet counters
        drop_counter = tcp_report.get(
            "firewall_drop_counter"
        )

        if drop_counter:
            d1, d2 = st.columns(2)

            d1.metric(
                "Firewall Dropped Packets",
                drop_counter.get("packets", 0),
            )

            d2.metric(
                "Firewall Dropped Bytes",
                drop_counter.get("bytes", 0),
            )

        # Individual TCP test results
        tcp_rows = [
            {
                "Test": item["test"],
                "Expected": (
                    "ALLOW"
                    if item["expected_allowed"]
                    else "DENY"
                ),
                "Observed": (
                    "ALLOW"
                    if item["observed_allowed"]
                    else "DENY"
                ),
                "Passed": item["passed"],
                "Socket error": item.get(
                    "probe", {}
                ).get("socket_error"),
                "Error description": item.get(
                    "probe", {}
                ).get("error_description", ""),
            }
            for item in tcp_report["results"]
        ]

        st.dataframe(
            tcp_rows,
            width="stretch",
        )

        with st.expander(
            "View TCP verification report"
        ):
            st.json(tcp_report)

        st.download_button(
            label="Download TCP verification report",
            data=json.dumps(
                tcp_report,
                indent=2,
            ),
            file_name="real_tcp_results.json",
            mime="application/json",
        )

    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        st.error(
            f"Could not load TCP report: {exc}"
        )

else:
    st.info(
        "No TCP verification report found yet. "
        "Click Run TCP Network Tests."
    )

# ============================================================
# Multi-Protocol Policy Verification
# ============================================================

st.divider()
st.subheader("Multi-Protocol Policy Verification")

st.caption(
    "Policy-driven TCP and UDP verification using "
    "Linux network namespaces and nftables."
)

policy_report_path = (
    Path(__file__).resolve().parent
    / "results"
    / "policy_multi_protocol_results.json"
)

if policy_report_path.exists():
    with open(policy_report_path, "r", encoding="utf-8") as f:
        policy_report = json.load(f)

    policy_results = policy_report.get("results", [])

    total_tests = policy_report.get("total", 0)
    passed_tests = policy_report.get("passed", 0)

    tcp_tests = sum(
        r.get("protocol") == "tcp"
        for r in policy_results
    )

    udp_tests = sum(
        r.get("protocol") == "udp"
        for r in policy_results
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Assertions", total_tests)
    col2.metric("Passed", passed_tests)
    col3.metric("TCP Tests", tcp_tests)
    col4.metric("UDP Tests", udp_tests)

    if total_tests > 0 and passed_tests == total_tests:
        st.success("All policy assertions passed.")
    elif total_tests == 0:
        st.warning("No policy assertions were executed.")
    else:
        st.warning(
            f"{total_tests - passed_tests} assertions did not pass."
        )

    st.markdown("#### Assertion Results")

    table_rows = []

    for result in policy_results:
        table_rows.append({
            "Assertion": result.get("assertion_id"),
            "Protocol": result.get("protocol", "").upper(),
            "Source": result.get("source"),
            "Destination": result.get("destination"),
            "Port": result.get("port"),
            "Expected": result.get("expected"),
            "Observed": result.get("observed"),
            "Matched Rule": result.get("matched_rule"),
            "Packet Delta": result.get("packet_delta"),
            "Byte Delta": result.get("byte_delta"),
            "Status": (
                "PASS" if result.get("passed")
                else "FAIL"
            ),
        })

    st.dataframe(
        table_rows,
        width="stretch",
        hide_index=True,
    )

    st.markdown("#### Firewall Rule Counters")

    firewall_counters = policy_report.get(
        "firewall_counters", []
    )

    st.dataframe(
        firewall_counters,
        width="stretch",
        hide_index=True,
    )

    with st.expander("View Complete Verification Evidence"):
        st.json(policy_report)

else:
    st.warning(
        "No saved multi-protocol verification report found. "
        "Run the Linux verifier first."
    )

# ============================================================
# Adversarial Security Test Evaluation
# ============================================================

st.divider()
st.subheader("Adversarial Security Test Evaluation")

st.caption(
    "Comparison of the original policy assertions with "
    "automatically selected security tests."
)

evaluation_path = (
    Path(__file__).resolve().parent
    / "results"
    / "security_test_evaluation.json"
)

if evaluation_path.exists():
    with open(evaluation_path, "r", encoding="utf-8") as f:
        evaluation = json.load(f)

    original_count = evaluation["original_assertions"]
    expanded_count = evaluation["expanded_assertions"]
    total_mutants = evaluation["mutants"]
    original_detected = evaluation["original_detected"]
    expanded_detected = evaluation["expanded_detected"]

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Original Tests", original_count)
    col2.metric("Expanded Tests", expanded_count)
    col3.metric("Original Detection", original_detected)
    col4.metric(
        "Expanded Detection",
        expanded_detected,
        delta=f"+{expanded_detected - original_detected}",
    )

    st.markdown("#### Mutation Detection Comparison")

    comparison = [
        {
            "Suite": "Original",
            "Assertions": original_count,
            "Detected": original_detected,
            "Detection Rate (%)": round(
                100 * original_detected / total_mutants, 1
            ) if total_mutants else 0,
        },
        {
            "Suite": "Expanded",
            "Assertions": expanded_count,
            "Detected": expanded_detected,
            "Detection Rate (%)": round(
                100 * expanded_detected / total_mutants, 1
            ) if total_mutants else 0,
        },
    ]

    st.dataframe(
        comparison,
        width="stretch",
        hide_index=True,
    )

    st.markdown("#### Access-Expansion Detection")

    access_total = evaluation["access_expanding_mutants"]
    access_detected = evaluation["access_expansions_detected"]

    if access_total:
        st.progress(
            access_detected / access_total,
            text=(
                f"{access_detected}/{access_total} "
                "access-expanding mutants detected"
            ),
        )

    st.markdown("#### Newly Detected Mutations")

    newly_detected = [
        {
            "Mutation": record["mutation"],
            "Operator": record["operator"],
            "Rule": record["rule_id"],
        }
        for record in evaluation["records"]
        if (
            record["expanded_detected"]
            and not record["original_detected"]
        )
    ]

    st.dataframe(
        newly_detected,
        width="stretch",
        hide_index=True,
    )

    with st.expander("View Full Security Evaluation Report"):
        st.json(evaluation)

else:
    st.warning(
        "Security evaluation report not found. "
        "Run the evaluation script first."
    )

# ============================================================
# Boundary-Based Security Test Evaluation
# ============================================================

st.divider()
st.header("Boundary-Based Security Test Evaluation")

st.caption(
    "Comparison of original assertions and boundary-enhanced "
    "security tests against observable held-out mutations."
)

boundary_report_path = Path(
    "results/boundary_observable_summary.json"
)

if boundary_report_path.exists():

    with open(boundary_report_path, encoding="utf-8") as f:
        boundary_reports = json.load(f)

    boundary_rows = []

    for report in boundary_reports:
        boundary_rows.append({
            "Scenario": report["scenario"],
            "Original Tests": report["original_tests"],
            "Boundary Tests Added": report["boundary_tests_added"],
            "Expanded Tests": report["expanded_tests"],
            "Observable Mutants": report["observable_mutants"],
            "Original Recall (%)": report["original_observable_recall"],
            "Expanded Recall (%)": report["expanded_observable_recall"],
        })

    boundary_df = pd.DataFrame(boundary_rows)

    st.subheader("Scenario Comparison")
    st.dataframe(boundary_df, use_container_width=True)

    total_observable = sum(
        r["observable_mutants"] for r in boundary_reports
    )

    total_original = sum(
        r["original_detected"] for r in boundary_reports
    )

    total_expanded = sum(
        r["expanded_detected"] for r in boundary_reports
    )

    original_recall = (
        100 * total_original / total_observable
        if total_observable else 0
    )

    expanded_recall = (
        100 * total_expanded / total_observable
        if total_observable else 0
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Observable Mutants",
        total_observable
    )

    col2.metric(
        "Original Recall",
        f"{original_recall:.1f}%"
    )

    col3.metric(
        "Boundary-Enhanced Recall",
        f"{expanded_recall:.1f}%",
        delta=f"+{expanded_recall-original_recall:.1f} pp"
    )

    st.subheader("Observable Mutation Recall")

    chart_df = boundary_df.set_index("Scenario")[
        ["Original Recall (%)", "Expanded Recall (%)"]
    ]

    st.bar_chart(chart_df)

    st.caption(
        "Results cover three network scenarios: guest isolation and enterprise "
        "segmentation (420 evaluated flows each), and cloud microservices "
        "(480 evaluated flows). Observable mutation recall is measured within "
        "these bounded flow spaces. The boundary-testing strategy was developed "
        "after examining earlier held-out failures, so these results demonstrate "
        "diagnostic effectiveness rather than fully independent generalization."
    )

else:
    st.warning(
        "Boundary evaluation report not found. "
        "Generate results/boundary_observable_summary.json first."
    )


# ============================================================
# Real Firewall Boundary Validation
# ============================================================

st.header("Real Firewall Boundary Validation")

st.caption(
    "Results from isolated Linux network namespaces using "
    "real TCP/UDP traffic and nftables firewall rules."
)

scenario_reports = {
    "Guest Isolation": "results/real_boundary_validation_results.json",
    "Enterprise Segmentation": "results/real_boundary_validation_enterprise_results.json",
    "Cloud Microservices": "results/real_boundary_validation_cloud_results.json",
}

selected_scenario = st.selectbox(
    "Select Network Scenario",
    list(scenario_reports.keys()),
    key="real_firewall_scenario",
)

real_boundary_path = Path(scenario_reports[selected_scenario])

if real_boundary_path.exists():

    with open(real_boundary_path, encoding="utf-8") as f:
        real_boundary_report = json.load(f)

    total = real_boundary_report["total_tests"]
    passed = real_boundary_report["passed"]
    failed = real_boundary_report["failed"]

    success_rate = 100 * passed / total if total else 0

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Tests", total)
    col2.metric("Passed", passed)
    col3.metric("Failed", failed)
    col4.metric("Success Rate", f"{success_rate:.1f}%")

    st.subheader("Original vs Boundary Tests")

    real_tests_df = pd.DataFrame(
        real_boundary_report["tests"]
    )

    category_summary = (
        real_tests_df.groupby("category")["passed"]
        .agg(["count", "sum"])
        .reset_index()
        .rename(
            columns={
                "category": "Test Category",
                "count": "Total",
                "sum": "Passed",
            }
        )
    )

    st.dataframe(category_summary, use_container_width=True)

    st.subheader("Individual Firewall Test Results")

    display_columns = {
        "test_id": "Test ID",
        "category": "Category",
        "source": "Source",
        "destination": "Destination",
        "protocol": "Protocol",
        "port": "Port",
        "expected": "Expected",
        "observed": "Observed",
        "matched_rule": "Matched Firewall Rule",
        "matched_rule_packets": "Matched Rule Packets",
        "passed": "Passed",
    }

    st.dataframe(
        real_tests_df.rename(columns=display_columns),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Observed Firewall Decisions")

    decision_counts = (
        real_tests_df["observed"]
        .value_counts()
        .rename_axis("Decision")
        .to_frame("Tests")
    )

    st.bar_chart(decision_counts)

    st.caption(
        f"These results validate the {selected_scenario} scenario "
        "against a real Linux nftables firewall using the tested "
        "TCP/UDP flows. They do not establish correctness for "
        "all possible traffic or network policies."
    )

else:
    st.warning(
        "Real firewall validation report not found. "
        "Run sudo python3 -m nettwin.real_boundary_validation first."
    )
