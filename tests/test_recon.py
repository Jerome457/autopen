"""Tests for the Milestone 1 reconnaissance module."""

import unittest

from modules.recon import parse_nmap_xml, validate_target


NMAP_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ReconTests(unittest.TestCase):
    def test_validate_target_accepts_single_ip(self) -> None:
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")

    def test_validate_target_rejects_hostname_and_network(self) -> None:
        for invalid_target in ("localhost", "192.168.1.0/24", ""):
            with self.subTest(target=invalid_target), self.assertRaises(ValueError):
                validate_target(invalid_target)

    def test_parse_nmap_xml_returns_only_open_services(self) -> None:
        self.assertEqual(
            parse_nmap_xml(NMAP_XML),
            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "version": "OpenSSH 8.9p1 Ubuntu",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
