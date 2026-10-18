
"""NetTwin: multi-assertion policy-driven TCP verification.

Uses an isolated network namespace per endpoint and a dedicated
router namespace with an nftables forward chain.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from nettwin.core import load, decide


PREFIX = "ntm-"
ROUTER = PREFIX + "router"
TABLE = "nettwin_acl"
ROOT = Path(__file__).resolve().parent.parent


def run(*args, check=True):
    return subprocess.run(
        list(map(str, args)),
        text=True,
        capture_output=True,
        check=check,
    )


def namespace(name):
    return PREFIX + name


def cleanup(names, servers):
    for process in servers:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()

    for name in reversed(names):
        run("ip", "netns", "del", name, check=False)


def create_topology(scenario, created):
    names = [ROUTER] + [
        namespace(node) for node in scenario.nodes
    ]

    existing = run("ip", "netns", "list").stdout

    for name in names:
        if any(
            line.split()[0] == name
            for line in existing.splitlines()
        ):
            raise RuntimeError(
                f"Namespace already exists: {name}"
            )

    for name in names:
        run("ip", "netns", "add", name)
        created.append(name)
        run("ip", "-n", name, "link", "set", "lo", "up")

    # A separate routed /30 link for each endpoint.
    for index, (node, address) in enumerate(
        scenario.nodes.items(), start=1
    ):
        ns = namespace(node)
        router_if = f"nr{index}"
        endpoint_if = f"ne{index}"

        # Each link uses a unique private transit subnet.
        router_ip = f"172.30.{index}.1"
        endpoint_ip = f"172.30.{index}.2"

        run(
            "ip", "link", "add", router_if,
            "type", "veth", "peer", "name", endpoint_if
        )
        run("ip", "link", "set", router_if, "netns", ROUTER)
        run("ip", "link", "set", endpoint_if, "netns", ns)

        run(
            "ip", "-n", ROUTER, "addr", "add",
            f"{router_ip}/30", "dev", router_if
        )
        run(
            "ip", "-n", ns, "addr", "add",
            f"{endpoint_ip}/30", "dev", endpoint_if
        )

        # Preserve the scenario's actual IP address as a loopback
        # /32, reachable through the endpoint's transit link.
        run(
            "ip", "-n", ns, "addr", "add",
            f"{address}/32", "dev", "lo"
        )

        run("ip", "-n", ROUTER, "link", "set", router_if, "up")
        run("ip", "-n", ns, "link", "set", endpoint_if, "up")

        run(
            "ip", "-n", ROUTER, "route", "add",
            f"{address}/32", "via", endpoint_ip,
            "dev", router_if
        )
        run(
            "ip", "-n", ns, "route", "add",
            "default", "via", router_ip,
            "dev", endpoint_if
        )

    run(
        "ip", "netns", "exec", ROUTER,
        "sysctl", "-w", "net.ipv4.ip_forward=1"
    )


def start_server(node, address, port):
    ns = namespace(node)

    process = subprocess.Popen(
        [
            "ip", "netns", "exec", ns,
            "python3", "-m", "http.server",
            str(port), "--bind", address
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    for _ in range(30):
        if process.poll() is not None:
            error = process.stderr.read().decode(
                errors="replace"
            )
            raise RuntimeError(
                f"Server {node}:{port} failed: {error}"
            )

        probe = run(
            "ip", "netns", "exec", ns,
            "python3", "-c",
            (
                "import socket; "
                f"s=socket.create_connection(({address!r}, {port}), 1); "
                "s.close()"
            ),
            check=False,
        )

        if probe.returncode == 0:
            return process

        time.sleep(0.1)

    raise RuntimeError(
        f"Server {node}:{port} did not become ready"
    )

def start_udp_server(node, address, port):
    """Start an isolated UDP echo server."""
    ns = namespace(node)

    process = subprocess.Popen(
        [
            "ip", "netns", "exec", ns,
            sys.executable, "-m", "nettwin.policy_udp_test",
            "server", address, str(port),
        ],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    # UDP has no handshake, so this checks that the
    # server process stays alive, not that packets arrive.
    time.sleep(0.3)

    if process.poll() is not None:
        error = process.stderr.read().decode(
            errors="replace"
        )
        raise RuntimeError(
            f"UDP server {node}:{port} failed: {error}"
        )

    return process


def probe_udp(source, source_ip, destination_ip, port):
    """Send a UDP payload and verify the echo response."""
    result = run(
        "ip", "netns", "exec", namespace(source),
        sys.executable, "-m", "nettwin.policy_udp_test",
        "client", source_ip, destination_ip, str(port),
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"UDP probe failed: {result.stderr}"
        )

    return json.loads(result.stdout)

def configure_firewall(scenario):
    run(
        "ip", "netns", "exec", ROUTER,
        "nft", "add", "table", "inet", TABLE
    )

    run(
        "ip", "netns", "exec", ROUTER,
        "nft", "add", "chain", "inet", TABLE, "forward",
        "{ type filter hook forward priority 0; policy accept; }"
    )
    # Allow response packets belonging to established connections.
    # This must appear before the scenario's ordered ACL rules.
    run(
        "ip", "netns", "exec", ROUTER,
        "nft", "add", "rule", "inet", TABLE, "forward",
        "ct", "state", "established,related",
        "counter", "accept"
    )
    # Preserve JSON rule order: nftables evaluates these in order.
    for rule in scenario.rules:
        source = (
            scenario.nodes[rule.source]
            if rule.source in scenario.nodes
            else rule.source
        )
        destination = (
            scenario.nodes[rule.destination]
            if rule.destination in scenario.nodes
            else rule.destination
        )

        command = [
            "ip", "netns", "exec", ROUTER,
            "nft", "add", "rule", "inet", TABLE, "forward"
        ]

        if source != "any":
            command += ["ip", "saddr", source]

        if destination != "any":
            command += ["ip", "daddr", destination]

        if rule.protocol != "any":
            command += ["meta", "l4proto", rule.protocol]

        if rule.port:
            if rule.protocol not in ("tcp", "udp"):
                raise ValueError(
                    f"Unsupported port match in {rule.id}"
                )
            command += [
                rule.protocol, "dport", str(rule.port)
            ]

        command += [
            "counter",
            "accept" if rule.action == "ALLOW" else "drop"
        ]

        run(*command)

    run(
        "ip", "netns", "exec", ROUTER,
        "nft", "add", "rule", "inet", TABLE, "forward",
        "counter",
        "accept" if scenario.default_action == "ALLOW"
        else "drop"
    )

def get_firewall_counters():
    """Read packet counters from the generated nftables chain."""
    result = run(
        "ip", "netns", "exec", ROUTER,
        "nft", "-j", "list", "chain",
        "inet", TABLE, "forward"
    )

    data = json.loads(result.stdout)
    counters = []

    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue

        for expression in rule.get("expr", []):
            counter = expression.get("counter")
            if counter is not None:
                counters.append({
                    "packets": counter.get("packets", 0),
                    "bytes": counter.get("bytes", 0),
                })

    return counters

def probe(source, source_ip, destination_ip, port):
    code = (
        "import json,socket; "
        "s=socket.socket(); s.settimeout(2); "
        f"s.bind(({source_ip!r},0)); "
        f"r=s.connect_ex(({destination_ip!r},{port})); "
        "print(json.dumps({'allowed':r==0,'socket_error':r})); "
        "s.close()"
    )

    result = run(
        "ip", "netns", "exec", namespace(source),
        "python3", "-c", code
    )

    return json.loads(result.stdout)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo.")

    scenario = load(
        str(ROOT / "benchmarks" / "guest_isolation.json")
    )

    assertions = [
        a for a in scenario.assertions
        if a.flow.protocol in ("tcp","udp")
    ]

    created = []
    servers = []

    try:
        create_topology(scenario, created)
        listeners = sorted({
            (
                a.flow.destination,
                scenario.nodes[a.flow.destination],
                a.flow.port,
                a.flow.protocol,
            )
            for a in assertions
        })

        for node, address, port, protocol in listeners:
            if protocol == "tcp":
                servers.append(
                    start_server(node, address, port)
                )
            elif protocol == "udp":
                servers.append(
                    start_udp_server(node, address, port)
                )

        # A single ordered firewall is used for every assertion.
        configure_firewall(scenario)

        results = []

        for assertion in assertions:
            flow = assertion.flow
            source_ip = scenario.nodes[flow.source]
            destination_ip = scenario.nodes[flow.destination]

            model_action, matched_rule = decide(
                scenario, flow
            )

            # Capture firewall counters before this specific probe.
            counters_before = get_firewall_counters()

            if flow.protocol == "tcp":
                observed_probe = probe(
                    flow.source, source_ip,
                    destination_ip, flow.port
                )
            elif flow.protocol == "udp":
                observed_probe = probe_udp(
                    flow.source, source_ip,
                    destination_ip, flow.port
                )

            # Capture counters immediately after this probe.
            counters_after = get_firewall_counters()

            counter_rule_ids = (
                ["CONNECTION_TRACKING"]
                + [rule.id for rule in scenario.rules]
                + ["DEFAULT"]
            )

            if (
                len(counters_before) != len(counter_rule_ids)
                or len(counters_after) != len(counter_rule_ids)
            ):
                raise RuntimeError(
                    "Firewall counter count does not match ACL rules."
            )
            before_by_rule = dict(zip(
                counter_rule_ids, counters_before
            ))
            after_by_rule = dict(zip(
                counter_rule_ids, counters_after
            ))

            before = before_by_rule[matched_rule]
            after = after_by_rule[matched_rule]

            packet_delta = (
                after["packets"] - before["packets"]
            )

            byte_delta = (
                after["bytes"] - before["bytes"]
            )

            # Keep the raw connection outcome separate from
            # firewall enforcement evidence.
            observed = (
                "ALLOW" if observed_probe["allowed"]
                else "DENY")

            results.append({
                "assertion_id": assertion.id,
                "source": flow.source,
                "destination": flow.destination,
                "protocol": flow.protocol,
                "port": flow.port,
                "expected": assertion.expected,
                "model_action": model_action,
                "matched_rule": matched_rule,
                "observed": observed,
                "probe": observed_probe,
                "passed": observed == assertion.expected,
                "packet_delta": packet_delta,
                "byte_delta": byte_delta,
            })
        firewall_counters = get_firewall_counters()
        counter_rule_ids = (
            ["CONNECTION_TRACKING"]
            + [rule.id for rule in scenario.rules]
            + ["DEFAULT"]
        )
        if len(firewall_counters) != len(counter_rule_ids):
            raise RuntimeError(
                "Firewall counter count does not match "
                "the generated ACL rule count."
            )

        labeled_counters = [
            {
                "rule_id": rule_id,
                "packets": counter["packets"],
                "bytes": counter["bytes"],
            }
            for rule_id, counter in zip(
                counter_rule_ids, firewall_counters
            )
        ]

        counter_by_rule = {
            item["rule_id"]: item
            for item in labeled_counters
        }

        for item in results:
            matched_rule = item["matched_rule"]
            counter = counter_by_rule.get(matched_rule)

            item["firewall_evidence"] = counter

            if item["expected"] == "DENY":
                item["passed"] = (
                    item["observed"] == "DENY"
                    and item["model_action"] == "DENY"
                    and item["packet_delta"] > 0
                )
            else:
                item["passed"] = (
                    item["observed"] == "ALLOW"
                    and item["model_action"] == "ALLOW"
                )
        report = {
            "firewall_counters": labeled_counters,
            "backend": "linux-policy-multi-protocol",
            "scenario": scenario.name,
            "total": len(results),
            "passed": sum(
                item["passed"] for item in results
            ),
            "results": results,
        }

        print(json.dumps(report, indent=2))

        if report["passed"] != report["total"]:
            sys.exit(1)

    finally:
        cleanup(created, servers)


if __name__ == "__main__":
    main()
