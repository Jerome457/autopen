"""Tests for resilient PyShark packet metadata extraction."""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from modules.pcap_parser import packet_to_record, parse_pcap


class FakeCapture(list):
    def __init__(self, packets: list[object]) -> None:
        super().__init__(packets)
        self.closed = False

    def close(self) -> None:
        self.closed = True


class PcapParserTests(unittest.TestCase):
    def test_packet_to_record_handles_tcp_and_missing_fields(self) -> None:
        packet = SimpleNamespace(
            sniff_time=datetime(2026, 10, 3, 10, 0, tzinfo=timezone.utc),
            ip=SimpleNamespace(src="127.0.0.1", dst="127.0.0.1"),
            tcp=SimpleNamespace(srcport="40000", dstport="22"),
            length="74",
            highest_layer="TCP",
        )

        self.assertEqual(
            packet_to_record(packet),
            {
                "timestamp": "2026-10-03T10:00:00+00:00",
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "src_port": 40000,
                "dst_port": 22,
                "length": 74,
            },
        )

    def test_packet_to_record_handles_arp_without_ports(self) -> None:
        packet = SimpleNamespace(
            sniff_timestamp="1791011400.0",
            arp=SimpleNamespace(
                src_proto_ipv4="192.0.2.1", dst_proto_ipv4="192.0.2.2"
            ),
            length="42",
            highest_layer="ARP",
        )

        record = packet_to_record(packet)

        self.assertEqual(record["protocol"], "ARP")
        self.assertEqual(record["src_ip"], "192.0.2.1")
        self.assertEqual(record["dst_ip"], "192.0.2.2")
        self.assertIsNone(record["src_port"])
        self.assertIsNone(record["dst_port"])

    def test_parse_pcap_returns_records_and_closes_capture(self) -> None:
        packet = SimpleNamespace(highest_layer="DATA", length="10")
        fake_capture = FakeCapture([packet])
        fake_pyshark = SimpleNamespace(FileCapture=Mock(return_value=fake_capture))

        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "capture.pcap"
            capture_path.touch()
            with patch("modules.pcap_parser.pyshark", fake_pyshark):
                records = parse_pcap(capture_path)

        self.assertEqual(records[0]["protocol"], "DATA")
        self.assertTrue(fake_capture.closed)
        fake_pyshark.FileCapture.assert_called_once_with(
            str(capture_path), keep_packets=False
        )


if __name__ == "__main__":
    unittest.main()
