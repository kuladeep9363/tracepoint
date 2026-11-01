"""Convert parser output into the stable, frontend-facing JSON shape."""

from app.parser import ParsedCapture


def capture_to_json(capture: ParsedCapture, filename: str) -> dict:
    return {
        "capture": {
            "filename": filename,
            "packet_count": len(capture.packets),
            "skipped_packet_count": capture.skipped_packets,
        },
        "packets": [
            {
                "number": packet.number,
                "timestamp": packet.timestamp,
                "source_ip": packet.source_ip,
                "source_port": packet.source_port,
                "destination_ip": packet.destination_ip,
                "destination_port": packet.destination_port,
                "protocol": packet.protocol,
                "description": packet.description,
                "flags": packet.flags,
                "labels": packet.labels,
                "metadata": packet.metadata,
            }
            for packet in capture.packets
        ],
    }
