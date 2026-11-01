"""Normalize packet JSON, group related traffic, and create explainable findings."""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Packet:
    number: int
    time: datetime
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    protocol: str
    description: str
    flags: set[str] = field(default_factory=set)
    labels: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def source(self) -> str:
        return _endpoint(self.source_ip, self.source_port)

    @property
    def destination(self) -> str:
        return _endpoint(self.destination_ip, self.destination_port)


@dataclass
class Event:
    time: datetime
    source: str
    destination: str
    protocol: str
    summary: str
    severity: str
    color: str
    classification: str
    explanation: dict[str, Any]
    details: dict[str, Any]


def _endpoint(address: str | None, port: int | None) -> str:
    if address is None:
        return "Unknown"
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def normalize_packets(raw_packets: list[dict[str, Any]]) -> list[Packet]:
    packets = []
    for index, raw in enumerate(raw_packets, start=1):
        value = raw.get("timestamp") or raw.get("time")
        if not isinstance(value, str):
            raise ValueError(f"Packet {index} has no valid timestamp.")
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Packet {index} has an invalid timestamp.") from exc
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        metadata = raw.get("metadata")
        packets.append(Packet(
            number=int(raw.get("number") or index), time=timestamp,
            source_ip=raw.get("source_ip"), source_port=raw.get("source_port"),
            destination_ip=raw.get("destination_ip"), destination_port=raw.get("destination_port"),
            protocol=str(raw.get("protocol") or "OTHER").upper(),
            description=str(raw.get("description") or "Packet observed"),
            flags={str(flag).upper() for flag in (raw.get("flags") or [])},
            labels={str(label).lower() for label in (raw.get("labels") or [])},
            metadata=metadata if isinstance(metadata, dict) else {},
        ))
    return sorted(packets, key=lambda packet: (packet.time, packet.number))


def _explanation(what: str, why: str, response: list[str], **extra: str) -> dict[str, Any]:
    return {"what_this_means": what, "why_it_was_flagged": why,
            "suggested_response": response, **extra}


def _event(packet: Packet, summary: str, *, protocol: str | None = None,
           severity: str = "info", color: str = "neutral", details: dict | None = None,
           source: str | None = None, destination: str | None = None,
           classification: str = "needs review", explanation: dict | None = None) -> Event:
    return Event(packet.time, source or packet.source, destination or packet.destination,
                 protocol or packet.protocol, summary, severity, color, classification,
                 explanation or _explanation(
                     "This row records network activity seen in the capture.",
                     "No specific fault or attack pattern was confirmed by the available metadata.",
                     ["Review the surrounding traffic if this activity is unexpected."],
                     detection_assessment="Informational observation; the capture may not contain enough context to classify it."),
                 details or {})


def _indices_details(packets: list[Packet], indices: list[int], **extra: Any) -> dict[str, Any]:
    return {"packet_numbers": [packets[i].number for i in indices], "packet_count": len(indices), **extra}


def _handshake_events(packets: list[Packet], used: set[int]) -> list[Event]:
    events = []
    for i, syn in enumerate(packets):
        if i in used or syn.protocol != "TCP" or "SYN" not in syn.flags or "ACK" in syn.flags:
            continue
        rev = (syn.destination_ip, syn.destination_port, syn.source_ip, syn.source_port)
        synack = next((j for j in range(i + 1, len(packets)) if j not in used and
                       packets[j].protocol == "TCP" and "SYN" in packets[j].flags and "ACK" in packets[j].flags and
                       (packets[j].source_ip, packets[j].source_port, packets[j].destination_ip, packets[j].destination_port) == rev), None)
        if synack is None:
            continue
        ack = next((j for j in range(synack + 1, len(packets)) if j not in used and packets[j].protocol == "TCP" and
                    "ACK" in packets[j].flags and "SYN" not in packets[j].flags and
                    (packets[j].source_ip, packets[j].source_port, packets[j].destination_ip, packets[j].destination_port) ==
                    (syn.source_ip, syn.source_port, syn.destination_ip, syn.destination_port)), None)
        if ack is None:
            continue
        chosen = [i, synack, ack]
        used.update(chosen)
        events.append(_event(syn, "TCP 3-way handshake", severity="low", color="teal",
            details=_indices_details(packets, chosen, handshake_type="TCP three-way", completed=True),
            explanation=_explanation("A TCP connection was established successfully.",
                "The capture contains the opening request, server reply, and final confirmation.",
                ["No action is needed unless this connection is unexpected."],
                detection_assessment="Normal connection setup; no attack is implied.")))
    return events


def _dns_events(packets: list[Packet], used: set[int]) -> list[Event]:
    pending: dict[tuple, list[int]] = defaultdict(list)
    events = []
    for i, packet in enumerate(packets):
        if i in used or packet.protocol not in {"UDP", "TCP"} or not ("dns" in packet.labels or 53 in {packet.source_port, packet.destination_port}):
            continue
        meta = packet.metadata
        reverse = (packet.protocol, packet.destination_ip, packet.destination_port, packet.source_ip, packet.source_port)
        key = (packet.protocol, packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port)
        txid = meta.get("dns_id")
        candidate = next((j for j in pending.get(reverse, []) if
                          (txid is None or packets[j].metadata.get("dns_id") in (None, txid)) and
                          (packet.time-packets[j].time).total_seconds() <= 10), None)
        if candidate is None:
            pending[key].append(i)
            continue
        pending[reverse].remove(candidate)
        used.update((candidate, i))
        query, response = packets[candidate], packet
        failed = bool(response.metadata.get("dns_rcode"))
        delay_ms = round((response.time - query.time).total_seconds() * 1000, 1)
        delayed = delay_ms > 2000
        domain = query.metadata.get("dns_query")
        answers = response.metadata.get("dns_answers", [])
        explanation = (_explanation("The DNS lookup did not succeed.",
            f"The response for {domain or 'a name'} reported an error code ({response.metadata.get('dns_rcode')}).",
            ["Check the configured DNS resolver and whether the requested name should exist."],
            likely_cause="The name may be invalid, unavailable, or blocked by the resolver.",
            troubleshooting_step="Retry the lookup using an approved resolver and compare the result.") if failed else
            _explanation("The DNS lookup took longer than expected to receive a reply.",
                f"The matching response arrived after {delay_ms} ms.",
                ["Check resolver health and network latency if this delay happens repeatedly."],
                likely_cause="A slow resolver or congested network may have delayed the reply.",
                troubleshooting_step="Compare response times across several lookups and check resolver status.") if delayed else
            _explanation("A domain name was looked up and a DNS response was observed.",
                f"The response matched the query for {domain or 'a name'} within 10 seconds.",
                ["No action is needed unless the returned address is unexpected."],
                detection_assessment="A paired lookup alone is normal and is not evidence of hijacking."))
        events.append(_event(query, "DNS lookup failure" if failed else "Unusually slow DNS response" if delayed else "DNS query and response",
            protocol="DNS", severity="medium" if failed or delayed else "low", color="amber" if failed or delayed else "teal",
            classification="likely fault" if failed or delayed else "needs review",
            explanation=explanation,
            details=_indices_details(packets, [candidate, i], match_basis="Reversed IP/port tuple within 10 seconds",
                domain_name=domain, response_ips=answers, response_code=response.metadata.get("dns_rcode"), response_delay_ms=delay_ms,
                query_summary=query.metadata.get("dns_start_line"), response_summary=response.metadata.get("dns_start_line"))))
    return events


def _http_events(packets: list[Packet], used: set[int]) -> list[Event]:
    pending: dict[tuple, list[int]] = defaultdict(list)
    events = []
    for i, packet in enumerate(packets):
        if i in used or packet.protocol != "TCP":
            continue
        kind = packet.metadata.get("http_type")
        if kind not in {"request", "response"}:
            continue
        reverse = (packet.destination_ip, packet.destination_port, packet.source_ip, packet.source_port)
        key = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port)
        if kind == "request":
            pending[key].append(i)
            continue
        match = next((j for j in pending.get(reverse, []) if (packet.time-packets[j].time).total_seconds() <= 30), None)
        if match is None:
            continue
        pending[reverse].remove(match)
        used.update((match, i))
        request = packets[match]
        delay_ms = round((packet.time - request.time).total_seconds() * 1000, 1)
        request_line = request.metadata.get("http_start_line")
        response_line = packet.metadata.get("http_start_line")
        slow = delay_ms > 5000
        events.append(_event(request, "Slow HTTP response" if slow else "HTTP request and response", protocol="HTTP", color="amber" if slow else "teal", severity="medium" if slow else "low",
            classification="likely fault" if slow else "needs review",
            explanation=_explanation("The web server took a long time to reply." if slow else "A web request and its matching response were observed.",
                f"The matching response arrived after {delay_ms} ms." if slow else "The response came back on the reversed connection within 30 seconds.",
                ["Check server load and network latency if this delay happens repeatedly." if slow else "No action is needed unless the request or response is unexpected."],
                **({"likely_cause": "Server load or network congestion may have delayed the reply.", "troubleshooting_step": "Compare response times and check the web server's health."} if slow else {"detection_assessment": "The row represents one request-response pair; adjacent HTTP packets are not merged by flow alone."})),
            details=_indices_details(packets, [match, i], basis="One parsed request matched to the reversed connection response within 30 seconds",
                method=request.metadata.get("http_method"), path=request.metadata.get("http_path"),
                response_status=packet.metadata.get("http_status"), response_delay_ms=delay_ms, request=request_line, response=response_line)))
    return events


def _finding(packet: Packet, summary: str, classification: str, severity: str, color: str,
             what: str, why: str, response: list[str], details: dict[str, Any], **extra: str) -> Event:
    return _event(packet, summary, severity=severity, color=color, classification=classification,
        details=details, explanation=_explanation(what, why, response, **extra))


def _detection_events(packets: list[Packet], used: set[int]) -> list[Event]:
    events = []
    # A burst or scan stays as one direction-specific event so packet evidence is unambiguous.
    scans: dict[tuple, list[int]] = defaultdict(list)
    bursts: dict[tuple, list[int]] = defaultdict(list)
    for i, p in enumerate(packets):
        if i in used:
            continue
        if p.source_ip and p.destination_ip and p.destination_port is not None:
            scans[(p.source_ip, p.destination_ip, int(p.time.timestamp() // 10))].append(i)
        if p.destination_ip:
            bursts[(p.destination_ip, p.destination_port, int(p.time.timestamp() // 5))].append(i)
    for (src, dst, bucket), inds in scans.items():
        ports = {packets[i].destination_port for i in inds}
        if len(ports) < 10:
            continue
        used.update(inds); p = packets[inds[0]]
        events.append(_finding(p, "Possible port scan", "possible attack", "medium", "amber",
            "One host contacted many different ports on another host.",
            f"{len(ports)} destination ports were contacted within a 10-second window.",
            ["Check whether the source is an approved scanner.", "Review the target's exposed services and apply suitable access limits."],
            _indices_details(packets, inds, unique_destination_ports=len(ports), window_seconds=10),
            detection_assessment="This pattern can indicate service discovery, but authorized inventory scans can look the same.",
            suspicious_reason="Many destination ports were contacted in a short time.", immediate_action="Confirm whether the source is authorized before blocking it."))
    for (dst, port, bucket), inds in bursts.items():
        inds = [i for i in inds if i not in used]
        sources = {packets[i].source_ip for i in inds if packets[i].source_ip}
        if len(inds) < 100:
            continue
        used.update(inds); p = packets[inds[0]]; distributed = len(sources) >= 10
        events.append(_finding(p, "Possible DDoS burst" if distributed else "Possible DoS burst", "possible attack", "high", "red",
            "A large burst of traffic reached one destination.",
            f"{len(inds)} packets arrived in 5 seconds from {len(sources)} distinct source IPs.",
            ["Check whether the service is affected.", "Ask the network or hosting team about rate limiting or upstream filtering."],
            _indices_details(packets, inds, distinct_source_ips=len(sources), window_seconds=5),
            detection_assessment="A traffic burst is suspicious, but a flash crowd or load test can produce a similar pattern.",
            suspicious_reason="Traffic volume crossed the configured burst threshold.", immediate_action="Check service health and preserve the capture for incident review."))

    # ARP sender IP mapped to multiple hardware addresses in a short observation window.
    arp_claims: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for i, p in enumerate(packets):
        if p.protocol == "ARP":
            ip, mac = p.metadata.get("arp_sender_ip", p.source_ip), p.metadata.get("arp_sender_mac")
            if ip and mac:
                arp_claims[ip][str(mac).lower()].append(i)
    for ip, mappings in arp_claims.items():
        if len(mappings) < 2:
            continue
        inds = sorted({i for values in mappings.values() for i in values})
        if (packets[inds[-1]].time-packets[inds[0]].time).total_seconds() > 60:
            continue
        used.update(inds); p = packets[inds[0]]
        conflicting_reply = any(packets[i].metadata.get("arp_op") == 2 for i in inds)
        evidence = _indices_details(packets, inds, claimed_ip=ip,
            arp_mappings={mac: [packets[i].number for i in values] for mac, values in mappings.items()})
        if conflicting_reply:
            events.append(_finding(p, "Possible ARP spoofing", "possible attack", "high", "red",
                "Conflicting ARP replies announced different hardware addresses for the same local IP.",
                f"ARP packets claimed {ip} from {len(mappings)} different hardware addresses, including a reply.",
                ["Compare the IP-to-device mapping with a trusted router or asset list.", "Ask the network administrator to investigate before isolating a device."], evidence,
                detection_assessment="Conflicting mappings can also occur during failover or device replacement.",
                suspicious_reason="Conflicting ARP ownership claims included a reply that could redirect local traffic.",
                immediate_action="Verify the mapping with a trusted network source."))
        else:
            events.append(_finding(p, "ARP address conflict", "likely fault", "medium", "amber",
                "Two devices appear to be claiming the same local IP address.",
                f"ARP announcements associated {ip} with {len(mappings)} hardware addresses within 60 seconds.",
                ["Check for duplicate static addresses or overlapping DHCP leases."], evidence,
                likely_cause="A duplicate address or expected device failover may have caused competing claims.",
                troubleshooting_step="Compare the claims with DHCP leases and the network's device inventory."))

    # Multiple DHCP offer servers for one client/transaction.
    dhcp_offers: dict[str, list[int]] = defaultdict(list)
    for i, p in enumerate(packets):
        if p.metadata.get("dhcp_message_type") in {"offer", "2", 2}:
            dhcp_offers[str(p.metadata.get("dhcp_xid", p.metadata.get("dhcp_client", "unknown")))].append(i)
    for xid, inds in dhcp_offers.items():
        servers = {packets[i].metadata.get("dhcp_server_id") or packets[i].metadata.get("source_mac") or packets[i].source_ip for i in inds}
        if len(servers) > 1:
            used.update(inds); p = packets[inds[0]]
            events.append(_finding(p, "Possible rogue DHCP server", "possible attack", "high", "red",
                "More than one DHCP server offered network settings to the same client.",
                f"The same DHCP exchange ({xid}) received offers from {len(servers)} server identities.",
                ["Confirm the approved DHCP server list.", "Ask the network administrator to trace and disable any unauthorized offer source."],
                _indices_details(packets, inds, server_identities=sorted(str(x) for x in servers)),
                detection_assessment="Multiple offers can be legitimate during failover, so verify server authorization.",
                suspicious_reason="An unrecognized server may provide unsafe gateway or DNS settings.", immediate_action="Compare each offer source with the approved DHCP server list."))

    # Same name receives inconsistent answers from distinct resolvers in a short time.
    dns_results: dict[str, list[int]] = defaultdict(list)
    for i, p in enumerate(packets):
        if p.metadata.get("dns_query") and p.metadata.get("dns_answers"):
            dns_results[str(p.metadata["dns_query"]).lower()].append(i)
    for name, inds in dns_results.items():
        if len(inds) < 2:
            continue
        recent = [i for i in inds if (packets[inds[-1]].time-packets[i].time).total_seconds() <= 60]
        resolvers = {packets[i].source_ip for i in recent}
        answers = {str(answer) for i in recent for answer in packets[i].metadata.get("dns_answers", [])}
        if len(resolvers) > 1 and len(answers) > 1:
            used.update(recent); p = packets[recent[0]]
            events.append(_finding(p, "Possible DNS hijacking", "possible attack", "high", "red",
                "Different DNS servers returned different addresses for the same domain.",
                f"{len(resolvers)} resolvers returned {len(answers)} different answers for {name} within 60 seconds.",
                ["Compare results with an approved resolver and check resolver settings.", "Ask the network administrator to investigate unexpected resolver changes."],
                _indices_details(packets, recent, domain_name=name, resolvers=sorted(str(x) for x in resolvers), answers=sorted(answers)),
                detection_assessment="CDNs and ordinary DNS changes can return different addresses; this is a review signal, not proof.",
                suspicious_reason="Resolver answers differed during a short period.", immediate_action="Validate the answers against a trusted resolver before changing network settings."))

    # Clear transport faults. RST packets are reportable, but not treated as attacks.
    for i, p in enumerate(packets):
        if i in used or p.protocol != "TCP" or "RST" not in p.flags:
            continue
        used.add(i)
        events.append(_finding(p, "TCP connection reset", "likely fault", "medium", "amber",
            "A TCP connection was closed abruptly.", "This packet carried a reset signal instead of a normal close.",
            ["Check whether the service was available and whether a firewall or application closed the connection."],
            _indices_details(packets, [i]), likely_cause="The service may be unavailable or a network device may have rejected the connection.",
            troubleshooting_step="Check service and firewall logs at this time."))

    # Repeated TCP segments with same direction and sequence metadata (metadata must be supplied).
    repeats: dict[tuple, list[int]] = defaultdict(list)
    for i, p in enumerate(packets):
        seq = p.metadata.get("tcp_sequence")
        if p.protocol == "TCP" and seq is not None and i not in used and (
                p.metadata.get("tcp_payload_length", 0) > 0 or "SYN" in p.flags or "FIN" in p.flags):
            repeats[(p.source_ip, p.source_port, p.destination_ip, p.destination_port, seq)].append(i)
    for key, inds in repeats.items():
        if len(inds) < 2 or (packets[inds[-1]].time-packets[inds[0]].time).total_seconds() > 10:
            continue
        used.update(inds); p = packets[inds[0]]
        events.append(_finding(p, "Possible TCP retransmission", "likely fault", "low", "amber",
            "The same TCP data appears to have been sent more than once.",
            f"The same sequence value appeared in {len(inds)} packets within 10 seconds.",
            ["Check for packet loss, congestion, or a weak network link."], _indices_details(packets, inds),
            likely_cause="Packet loss or delayed acknowledgements may cause a sender to retry.",
            troubleshooting_step="Review link quality and network device error counters."))
    for i, p in enumerate(packets):
        if i in used or not p.metadata.get("reported_mtu"):
            continue
        used.add(i)
        events.append(_finding(p, "Possible MTU mismatch", "likely fault", "low", "amber",
            "A network device reported that a packet was too large for the next link.",
            f"The reported next-hop MTU is {p.metadata['reported_mtu']} bytes.",
            ["Check MTU settings along the route and look for dropped large transfers."],
            _indices_details(packets, [i], reported_mtu=p.metadata["reported_mtu"]),
            likely_cause="Different link MTU settings can prevent larger packets from passing.",
            troubleshooting_step="Compare interface MTU values along the route."))
    return events


def _duplicate_ip_events(packets: list[Packet], used: set[int]) -> list[Event]:
    claims: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for i, p in enumerate(packets):
        mac = p.metadata.get("source_mac")
        if p.source_ip and mac:
            claims[p.source_ip][str(mac).lower()].append(i)
    events = []
    for ip, macs in claims.items():
        if len(macs) < 2:
            continue
        inds = sorted({i for values in macs.values() for i in values if i not in used})
        if len(inds) < 2:
            continue
        used.update(inds); p = packets[inds[0]]
        events.append(_finding(p, "Possible duplicate IP address", "likely fault", "medium", "amber",
            "Two devices appear to be using the same IP address.",
            f"Traffic sourced from {ip} was observed with {len(macs)} different hardware addresses.",
            ["Check DHCP leases and static address assignments for this IP."],
            _indices_details(packets, inds, claimed_ip=ip), likely_cause="An overlapping static address or stale DHCP lease may be present.",
            troubleshooting_step="Check the router's lease list and compare the devices' network settings."))
    return events


def analyze_packets(raw_packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packets = normalize_packets(raw_packets)
    used: set[int] = set()
    events = _handshake_events(packets, used)
    events.extend(_dns_events(packets, used))
    events.extend(_http_events(packets, used))
    events.extend(_detection_events(packets, used))
    events.extend(_duplicate_ip_events(packets, used))
    for i, packet in enumerate(packets):
        if i not in used:
            events.append(_event(packet, packet.description,
                details={"packet_numbers": [packet.number], "packet_count": 1}))
    events.sort(key=lambda event: event.time)
    rows = []
    for serial, event in enumerate(events, start=1):
        rows.append({"id": f"evt-{serial:06d}", "s_no": serial,
            "time": event.time.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "source": event.source, "destination": event.destination, "protocol": event.protocol,
            "summary": event.summary, "severity": event.severity, "color": event.color,
            "classification": event.classification, "explanation": event.explanation, "details": event.details})
    return rows
