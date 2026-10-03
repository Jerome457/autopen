"""Extract a compact forensic packet record from a PCAP using PyShark."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

try:
    import pyshark
except ImportError:  # The CLI reports this clearly when the optional dependency is absent.
    pyshark = None  # type: ignore[assignment]


DEFAULT_CAPTURE_PATH = Path("data/capture.pcap")


class PcapParserError(RuntimeError):
    """Raised when a capture cannot be parsed."""


class PacketInfo(TypedDict):
    """The packet metadata stored in SQLite."""

    timestamp: str | None
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int | None


def _attribute(value: Any, name: str) -> Any | None:
    try:
        return getattr(value, name)
    except (AttributeError, KeyError):
        return None


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str | None:
    return str(value) if value is not None else None


def packet_to_record(packet: Any) -> PacketInfo:
    """Convert one PyShark packet while tolerating absent protocol fields."""
    ip_layer = _attribute(packet, "ip") or _attribute(packet, "ipv6")
    arp_layer = _attribute(packet, "arp")
    tcp_layer = _attribute(packet, "tcp")
    udp_layer = _attribute(packet, "udp")
    icmp_layer = _attribute(packet, "icmp")
    icmpv6_layer = _attribute(packet, "icmpv6")

    src_ip = _text(_attribute(ip_layer, "src")) if ip_layer is not None else None
    dst_ip = _text(_attribute(ip_layer, "dst")) if ip_layer is not None else None
    if arp_layer is not None:
        src_ip = src_ip or _text(_attribute(arp_layer, "src_proto_ipv4"))
        dst_ip = dst_ip or _text(_attribute(arp_layer, "dst_proto_ipv4"))

    transport_layer = tcp_layer or udp_layer
    src_port = _integer(_attribute(transport_layer, "srcport"))
    dst_port = _integer(_attribute(transport_layer, "dstport"))

    if tcp_layer is not None:
        protocol = "TCP"
    elif udp_layer is not None:
        protocol = "UDP"
    elif icmp_layer is not None:
        protocol = "ICMP"
    elif icmpv6_layer is not None:
        protocol = "ICMPV6"
    elif arp_layer is not None:
        protocol = "ARP"
    else:
        protocol = _text(_attribute(packet, "highest_layer")) or "UNKNOWN"
        protocol = protocol.upper()

    sniff_time = _attribute(packet, "sniff_time")
    if isinstance(sniff_time, datetime):
        timestamp = sniff_time.isoformat()
    elif sniff_time is not None:
        timestamp = str(sniff_time)
    else:
        timestamp = _text(_attribute(packet, "sniff_timestamp"))

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": _integer(_attribute(packet, "length")),
    }


def parse_pcap(capture_path: Path = DEFAULT_CAPTURE_PATH) -> list[PacketInfo]:
    """Parse all packets from a capture and always close the PyShark reader."""
    capture_path = Path(capture_path)
    if not capture_path.is_file():
        raise PcapParserError(f"Capture file does not exist: {capture_path}")
    if pyshark is None:
        raise PcapParserError(
            "PyShark is not installed. Activate the project virtual environment "
            "and install the dependencies from requirements.txt."
        )

    try:
        capture = pyshark.FileCapture(str(capture_path), keep_packets=False)
    except Exception as exc:
        raise PcapParserError(f"Unable to open capture {capture_path}: {exc}") from exc

    records: list[PacketInfo] = []
    parse_error: Exception | None = None
    try:
        records.extend(packet_to_record(packet) for packet in capture)
    except Exception as exc:
        parse_error = exc
    finally:
        try:
            capture.close()
        except Exception as exc:
            if parse_error is None:
                parse_error = exc

    if parse_error is not None:
        raise PcapParserError(f"Unable to parse capture {capture_path}: {parse_error}") from parse_error
    return records
