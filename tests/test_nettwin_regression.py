
import unittest

from nettwin.core import Flow, decide, load, verify
from nettwin.mutation import candidates


class TestNetTwinRegression(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.guest = load(
            "benchmarks/guest_isolation.json"
        )
        cls.enterprise = load(
            "benchmarks/enterprise_segmentation.json"
        )

    def test_guest_baseline(self):
        result = verify(self.guest)
        self.assertTrue(result["all_passed"])
        self.assertEqual(result["total"], 5)

    def test_enterprise_baseline(self):
        result = verify(self.enterprise)
        self.assertTrue(result["all_passed"])
        self.assertEqual(result["total"], 6)

    def test_default_deny(self):
        flow = Flow("guest", "database", "tcp", 3306)
        self.assertEqual(
            decide(self.guest, flow)[0], "DENY"
        )

    def test_guest_dns_allowed(self):
        flow = Flow("guest", "dns", "udp", 53)
        self.assertEqual(
            decide(self.guest, flow)[0], "ALLOW"
        )

    def test_guest_dns_wrong_port_denied(self):
        flow = Flow("guest", "dns", "udp", 22)
        self.assertEqual(
            decide(self.guest, flow)[0], "DENY"
        )

    def test_guest_dns_wrong_protocol_denied(self):
        flow = Flow("guest", "dns", "tcp", 53)
        self.assertEqual(
            decide(self.guest, flow)[0], "DENY"
        )

    def test_port_widening_detectable(self):
        mutant = next(
            m for name, m, _ in candidates(self.guest)
            if name == "change_port:guest_dns"
        )

        flow = Flow("guest", "dns", "udp", 22)

        self.assertEqual(
            decide(self.guest, flow)[0], "DENY"
        )
        self.assertEqual(
            decide(mutant, flow)[0], "ALLOW"
        )

    def test_protocol_widening_detectable(self):
        mutant = next(
            m for name, m, _ in candidates(self.guest)
            if name == "change_protocol:guest_dns"
        )

        flow = Flow("guest", "dns", "tcp", 53)

        self.assertEqual(
            decide(self.guest, flow)[0], "DENY"
        )
        self.assertEqual(
            decide(mutant, flow)[0], "ALLOW"
        )

    def test_guest_mutation_count(self):
        self.assertEqual(
            len(list(candidates(self.guest))), 34
        )

    def test_enterprise_mutation_count(self):
        self.assertEqual(
            len(list(candidates(self.enterprise))), 41
        )


if __name__ == "__main__":
    unittest.main()
