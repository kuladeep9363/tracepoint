"""Extract a compact set of packet metadata from classic PCAP and PCAPNG."""

from dataclasses import dataclass
from datetime import datetime, timezone
import socket

import dpkt

MAX_PACKETS = 100_000


class CaptureParseError(Exception):
    """Raised when the uploaded file is not a readable packet capture."""


@dataclass
class ParsedPacket:
    number: int
    timestamp: str
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str
    description: str
    flags: list[str]
    labels: list[str]
    metadata: dict


@dataclass
class ParsedCapture:
    packets: list[ParsedPacket]
    skipped_packets: int


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _ip_text(value: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(value) == 16 else socket.AF_INET, value)


def _reader(capture_file):
    """Choose a reader from the capture magic bytes, independent of filename."""
    magic = capture_file.read(4)
    capture_file.seek(0)
    if magic in {b"\x0a\x0d\x0d\x0a"}:
        return dpkt.pcapng.Reader(capture_file)
    return dpkt.pcap.Reader(capture_file)


def _decode_frame(frame: bytes) -> tuple[str | None, int | None, str | None, int | None, str, str, list[str], list[str], dict]:
    source_ip = destination_ip = None
    source_port = destination_port = None
    flags: list[str] = []
    labels: list[str] = []
    protocol = "OTHER"
    description = "Unclassified packet"
    metadata: dict = {}

    try:
        ethernet = dpkt.ethernet.Ethernet(frame)
        metadata["source_mac"] = ":".join(f"{byte:02x}" for byte in ethernet.src)
        metadata["destination_mac"] = ":".join(f"{byte:02x}" for byte in ethernet.dst)
        network = ethernet.data
        if isinstance(network, dpkt.ip.IP):
            source_ip, destination_ip = _ip_text(network.src), _ip_text(network.dst)
            transport = network.data
        elif isinstance(network, dpkt.ip6.IP6):
            source_ip, destination_ip = _ip_text(network.src), _ip_text(network.dst)
            transport = network.data
        elif isinstance(network, dpkt.arp.ARP):
            protocol, description = "ARP", "Address resolution traffic"
            source_ip = _ip_text(network.spa) if network.spa and len(network.spa) in (4, 16) else None
            destination_ip = _ip_text(network.tpa) if network.tpa and len(network.tpa) in (4, 16) else None
            labels.append("address-resolution")
            metadata.update({"arp_op": network.op,
                "arp_sender_ip": source_ip,
                "arp_target_ip": destination_ip,
                "arp_sender_mac": ":".join(f"{byte:02x}" for byte in network.sha),
                "arp_target_mac": ":".join(f"{byte:02x}" for byte in network.tha)})
            return source_ip, source_port, destination_ip, destination_port, protocol, description, flags, labels, metadata
        else:
            return source_ip, source_port, destination_ip, destination_port, protocol, description, flags, labels, metadata

        if isinstance(transport, dpkt.tcp.TCP):
            protocol = "TCP"
            source_port, destination_port = transport.sport, transport.dport
            flag_names = ((dpkt.tcp.TH_SYN, "SYN"), (dpkt.tcp.TH_ACK, "ACK"), (dpkt.tcp.TH_FIN, "FIN"),
                          (dpkt.tcp.TH_RST, "RST"), (dpkt.tcp.TH_PUSH, "PSH"), (dpkt.tcp.TH_URG, "URG"))
            flags = [name for bit, name in flag_names if transport.flags & bit]
            description = f"TCP {' '.join(flags)}" if flags else "TCP segment"
            metadata["tcp_sequence"] = transport.seq
            metadata["tcp_acknowledgement"] = transport.ack
            metadata["tcp_payload_length"] = len(transport.data)
            if source_port in {80, 8080} or destination_port in {80, 8080}:
                try:
                    line = transport.data.splitlines()[0].decode("latin-1", errors="replace").strip()
                    if line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ")):
                        parts = line.split(" ", 2)
                        metadata.update({"http_type": "request", "http_method": parts[0], "http_path": parts[1], "http_start_line": line})
                    elif line.startswith("HTTP/"):
                        parts = line.split(" ", 2)
                        metadata.update({"http_type": "response", "http_status": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None, "http_start_line": line})
                except (IndexError, UnicodeError, ValueError):
                    pass
        elif isinstance(transport, dpkt.udp.UDP):
            protocol = "UDP"
            source_port, destination_port = transport.sport, transport.dport
            description = "UDP datagram"
            if source_port in {67, 68} or destination_port in {67, 68}:
                try:
                    bootp = dpkt.dhcp.DHCP(transport.data)
                    options = {item[0]: item[1] for item in bootp.opts if item and item[0] != 255}
                    msg_type = options.get(53, b"")
                    metadata.update({"dhcp_xid": bootp.xid,
                        "dhcp_client": ":".join(f"{byte:02x}" for byte in bootp.chaddr[:6]),
                        "dhcp_message_type": {1: "discover", 2: "offer", 3: "request", 5: "ack"}.get(msg_type[0] if msg_type else None, str(msg_type[0]) if msg_type else None),
                        "dhcp_server_id": _ip_text(options[54]) if 54 in options else None})
                except (AttributeError, dpkt.UnpackError, IndexError, TypeError, ValueError):
                    pass
        elif isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            protocol = "ICMPv6" if isinstance(transport, dpkt.icmp6.ICMP6) else "ICMP"
            description = f"{protocol} message"
            metadata["icmp_type"] = transport.type
            metadata["icmp_code"] = transport.code
            # IPv4 fragmentation-needed (type 3/code 4) carries the next-hop MTU.
            if protocol == "ICMP" and transport.type == 3 and transport.code == 4:
                try:
                    metadata["reported_mtu"] = transport.data.mtu
                    description = "ICMP fragmentation-needed message"
                except AttributeError:
                    pass
        else:
            protocol = "IPv6" if isinstance(network, dpkt.ip6.IP6) else "IPv4"
            description = f"{protocol} packet"

        if source_port == 53 or destination_port == 53:
            labels.append("dns")
            description = f"{description} · DNS traffic"
            payload = getattr(transport, "data", b"")
            if payload:
                try:
                    dns = dpkt.dns.DNS(payload)
                    queries = [q.name.decode("ascii", errors="replace") if isinstance(q.name, bytes) else str(q.name) for q in dns.qd]
                    answers = []
                    for answer in dns.an:
                        value = getattr(answer, "ip", None) or getattr(answer, "ip6", None)
                        if value:
                            answers.append(_ip_text(value))
                    metadata.update({"dns_id": dns.id, "dns_is_response": bool(dns.qr),
                        "dns_query": queries[0] if queries else None, "dns_answers": answers,
                        "dns_rcode": dns.rcode if dns.qr else 0,
                        "dns_start_line": f"DNS {'response' if dns.qr else 'query'}: {queries[0]}" if queries else None})
                except (dpkt.UnpackError, AttributeError, IndexError, TypeError, ValueError):
                    pass
    except (dpkt.UnpackError, ValueError, IndexError, socket.error) as exc:
        raise ValueError("Malformed packet frame") from exc

    return source_ip, source_port, destination_ip, destination_port, protocol, description, flags, labels, metadata


def parse_capture(path: str) -> ParsedCapture:
    """Read packet records and extract IP/transport metadata."""
    packets: list[ParsedPacket] = []
    skipped = 0
    try:
        with open(path, "rb") as capture_file:
            reader = _reader(capture_file)
            for packet_number, (timestamp, frame) in enumerate(reader, start=1):
                if packet_number > MAX_PACKETS:
                    raise CaptureParseError(f"Capture contains more than {MAX_PACKETS:,} packets; split it into smaller files.")
                try:
                    src_ip, src_port, dst_ip, dst_port, protocol, description, flags, labels, metadata = _decode_frame(frame)
                    packets.append(ParsedPacket(
                        number=packet_number,
                        timestamp=_timestamp(timestamp),
                        source_ip=src_ip,
                        source_port=src_port,
                        destination_ip=dst_ip,
                        destination_port=dst_port,
                        protocol=protocol,
                        description=description,
                        flags=flags,
                        labels=labels,
                        metadata=metadata,
                    ))
                except (ValueError, OverflowError):
                    skipped += 1
    except CaptureParseError:
        raise
    except (OSError, dpkt.NeedData, dpkt.UnpackError, ValueError, TypeError) as exc:
        raise CaptureParseError("Could not parse this file as a supported PCAP or PCAPNG capture.") from exc

    if not packets and skipped == 0:
        raise CaptureParseError("The capture contains no packets.")
    if not packets:
        raise CaptureParseError("No readable packets were found in the capture.")
    return ParsedCapture(packets=packets, skipped_packets=skipped)
