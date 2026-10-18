
"""First policy-driven TCP packet experiment for NetTwin.

Runs the guest -> database TCP/5432 DENY assertion
inside isolated Linux network namespaces.
Requires root and Linux iproute2/nftables.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

from nettwin.core import load


CLIENT_NS = "nettwin-policy-guest"
SERVER_NS = "nettwin-policy-database"
TABLE = "nettwin_policy_test"
PORT = 5432


def run(*args, check=True):
    return subprocess.run(
        args,
        text=True,
        capture_output=True,
        check=check,
    )


def cleanup():
    for ns in (CLIENT_NS, SERVER_NS):
        run("ip", "netns", "del", ns, check=False)


def setup_network(source_ip, destination_ip):
    # Use a dedicated namespace pair, separate from existing tests.
    for ns in (CLIENT_NS, SERVER_NS):
        run("ip", "netns", "add", ns)

    run(
        "ip", "link", "add", "ntp-guest",
        "type", "veth", "peer", "name", "ntp-db"
    )

    run("ip", "link", "set", "ntp-guest", "netns", CLIENT_NS)
    run("ip", "link", "set", "ntp-db", "netns", SERVER_NS)

    run(
        "ip", "-n", CLIENT_NS, "addr", "add",
        f"{source_ip}/32", "dev", "ntp-guest"
    )
    run(
        "ip", "-n", SERVER_NS, "addr", "add",
        f"{destination_ip}/32", "dev", "ntp-db"
    )

    for ns, interface in (
        (CLIENT_NS, "ntp-guest"),
        (SERVER_NS, "ntp-db"),
    ):
        run("ip", "-n", ns, "link", "set", "lo", "up")
        run("ip", "-n", ns, "link", "set", interface, "up")

    run(
        "ip", "-n", CLIENT_NS, "route", "add",
        f"{destination_ip}/32", "dev", "ntp-guest"
    )
    run(
        "ip", "-n", SERVER_NS, "route", "add",
        f"{source_ip}/32", "dev", "ntp-db"
    )


def start_server(destination_ip):
    process = subprocess.Popen(
        [
            "ip", "netns", "exec", SERVER_NS,
            "python3", "-m", "http.server",
            str(PORT), "--bind", destination_ip
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    for _ in range(30):
        if process.poll() is not None:
            raise RuntimeError("TCP test server exited unexpectedly")

        probe = run(
            "ip", "netns", "exec", SERVER_NS,
            "python3", "-c",
            (
                "import socket; "
                f"s=socket.create_connection(({destination_ip!r}, {PORT}), 1); "
                "s.close()"
            ),
            check=False,
        )

        if probe.returncode == 0:
            return process

        time.sleep(0.1)

    raise RuntimeError("TCP server did not become ready")


def stop_server(process):
    if process is None or process.poll() is not None:
        return

    os.killpg(process.pid, signal.SIGTERM)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def probe_connection(destination_ip):
    code = (
        "import socket, json; "
        "s=socket.socket(); "
        "s.settimeout(2); "
        f"result=s.connect_ex(({destination_ip!r}, {PORT})); "
        "print(json.dumps({'allowed': result == 0, "
        "'socket_error': result})); "
        "s.close()"
    )

    result = run(
        "ip", "netns", "exec", CLIENT_NS,
        "python3", "-c", code
    )

    return json.loads(result.stdout)


def install_firewall(source_ip, destination_ip):
    run(
        "ip", "netns", "exec", SERVER_NS,
        "nft", "add", "table", "inet", TABLE
    )

    run(
        "ip", "netns", "exec", SERVER_NS,
        "nft", "add", "chain", "inet", TABLE, "input",
        "{ type filter hook input priority 0; policy accept; }"
    )

    run(
        "ip", "netns", "exec", SERVER_NS,
        "nft", "add", "rule", "inet", TABLE, "input",
        "ip", "saddr", source_ip,
        "ip", "daddr", destination_ip,
        "tcp", "dport", str(PORT),
        "counter", "drop"
    )


def firewall_counter():
    result = run(
        "ip", "netns", "exec", SERVER_NS,
        "nft", "list", "chain", "inet", TABLE, "input"
    )

    match = re.search(
        r"counter packets (\d+) bytes (\d+)",
        result.stdout,
    )

    if not match:
        return None

    return {
        "packets": int(match.group(1)),
        "bytes": int(match.group(2)),
    }


def main():
    scenario = load("benchmarks/guest_isolation.json")

    assertion = next(
        a for a in scenario.assertions
        if a.id == "db_denied"
    )

    source_ip = scenario.nodes[assertion.flow.source]
    destination_ip = scenario.nodes[assertion.flow.destination]

    server = None

    # Never silently replace namespaces belonging to another run.
    for ns in (CLIENT_NS, SERVER_NS):
        if run("ip", "netns", "list").stdout.find(ns) != -1:
            raise RuntimeError(
                f"Namespace {ns} already exists. "
                "Inspect it before retrying."
            )

    try:
        setup_network(source_ip, destination_ip)
        server = start_server(destination_ip)

        baseline = probe_connection(destination_ip)

        if not baseline["allowed"]:
            raise RuntimeError(
                "Baseline TCP connection failed; "
                "firewall behavior cannot be verified."
            )

        install_firewall(source_ip, destination_ip)
        blocked = probe_connection(destination_ip)
        counter = firewall_counter()

        observed = "DENY" if (
            not blocked["allowed"]
            and counter is not None
            and counter["packets"] > 0
        ) else "INCONCLUSIVE"

        report = {
            "backend": "linux-policy-tcp",
            "assertion_id": assertion.id,
            "source": assertion.flow.source,
            "destination": assertion.flow.destination,
            "protocol": "tcp",
            "port": PORT,
            "expected": assertion.expected,
            "baseline": baseline,
            "firewall_probe": blocked,
            "firewall_counter": counter,
            "observed": observed,
            "passed": observed == assertion.expected,
        }

        print(json.dumps(report, indent=2))

        if not report["passed"]:
            sys.exit(1)

    finally:
        if server is not None:
            stop_server(server)
        cleanup()


if __name__ == "__main__":
    main()
