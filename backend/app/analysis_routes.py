"""JSON and PCAP endpoints for creating frontend analysis rows."""

from pathlib import Path
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from app.event_analysis import analyze_packets
from app.parser import CaptureParseError, parse_capture
from app.uploads import MAX_UPLOAD_BYTES, save_upload

router = APIRouter()


class PacketInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    number: int | None = None
    timestamp: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str = "OTHER"
    description: str = "Packet observed"
    flags: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaptureInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    capture: dict[str, Any] = Field(default_factory=dict)
    packets: list[PacketInput]


@router.post("/events/analyze", summary="Convert parsed packet JSON to analysis rows")
async def create_events(payload: CaptureInput) -> dict:
    if not payload.packets:
        raise HTTPException(status_code=422, detail="The capture contains no packets.")
    try:
        events = analyze_packets([packet.model_dump() for packet in payload.packets])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"capture": payload.capture, "event_count": len(events), "events": events}


@router.post("/pcap/analyze", summary="Upload a PCAP and return analysis rows")
async def upload_and_analyze(file: UploadFile = File(...)) -> dict:
    suffix = Path((file.filename or "").replace("\\", "/")).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=415, detail="Unsupported file type. Upload a .pcap, .pcapng, or .cap file.")

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="tracepoint-", suffix=suffix, delete=False) as temp_file:
            temp_path = temp_file.name
        size = await save_upload(file, temp_path, MAX_UPLOAD_BYTES)
        parsed = parse_capture(temp_path)
        packet_json = [
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
            for packet in parsed.packets
        ]
        events = analyze_packets(packet_json)
        display_name = Path((file.filename or "capture").replace("\\", "/")).name
        return {
            "capture": {"filename": display_name, "size_bytes": size,
                        "packet_count": len(parsed.packets), "skipped_packet_count": parsed.skipped_packets},
            "event_count": len(events),
            "events": events,
        }
    except HTTPException:
        raise
    except CaptureParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        await file.close()


@router.get("/events/demo", summary="Browser-readable sample analysis response")
async def demo_events() -> dict:
    """Return deterministic grouped rows, including a large reciprocal scan example."""
    scan_packets = []
    scan_start = datetime(2026, 11, 1, 8, 15, 20, tzinfo=timezone.utc)
    for number in range(1, 239):
        forward = number % 2 == 1
        direction_index = (number + 1) // 2 if forward else number // 2
        scan_packets.append({
            "number": number,
            "timestamp": (scan_start + timedelta(milliseconds=number)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "source_ip": "192.168.1.20" if forward else "93.184.216.34",
            "source_port": 40000 + number,
            "destination_ip": "93.184.216.34" if forward else "192.168.1.20",
            "destination_port": (direction_index % 10) + 1,
            "protocol": "TCP",
            "description": "TCP segment",
            "flags": [],
        })

    sample_packets = scan_packets + [
        {"number": 239, "timestamp": "2026-11-01T08:15:30.000000Z", "source_ip": "192.168.1.20", "source_port": 51824, "destination_ip": "93.184.216.34", "destination_port": 443, "protocol": "TCP", "description": "TCP SYN", "flags": ["SYN"]},
        {"number": 240, "timestamp": "2026-11-01T08:15:30.010000Z", "source_ip": "93.184.216.34", "source_port": 443, "destination_ip": "192.168.1.20", "destination_port": 51824, "protocol": "TCP", "description": "TCP SYN ACK", "flags": ["SYN", "ACK"]},
        {"number": 241, "timestamp": "2026-11-01T08:15:30.020000Z", "source_ip": "192.168.1.20", "source_port": 51824, "destination_ip": "93.184.216.34", "destination_port": 443, "protocol": "TCP", "description": "TCP ACK", "flags": ["ACK"]},
        {"number": 242, "timestamp": "2026-11-01T08:15:31.000000Z", "source_ip": "192.168.1.20", "source_port": 53001, "destination_ip": "192.168.1.1", "destination_port": 53, "protocol": "UDP", "description": "UDP datagram · DNS traffic", "labels": ["dns"]},
        {"number": 243, "timestamp": "2026-11-01T08:15:31.040000Z", "source_ip": "192.168.1.1", "source_port": 53, "destination_ip": "192.168.1.20", "destination_port": 53001, "protocol": "UDP", "description": "UDP datagram · DNS traffic", "labels": ["dns"]},
        {"number": 244, "timestamp": "2026-11-01T08:15:32.000000Z", "source_ip": "192.168.1.20", "source_port": 52000, "destination_ip": "93.184.216.34", "destination_port": 80, "protocol": "TCP", "description": "HTTP GET request", "flags": ["PSH", "ACK"], "metadata": {"http_type": "request", "http_method": "GET", "http_path": "/", "http_start_line": "GET / HTTP/1.1"}},
        {"number": 245, "timestamp": "2026-11-01T08:15:32.080000Z", "source_ip": "93.184.216.34", "source_port": 80, "destination_ip": "192.168.1.20", "destination_port": 52000, "protocol": "TCP", "description": "HTTP response", "flags": ["PSH", "ACK"], "metadata": {"http_type": "response", "http_status": 200, "http_start_line": "HTTP/1.1 200 OK"}},
    ]
    events = analyze_packets(sample_packets)
    return {"capture": {"filename": "demo.pcap", "packet_count": len(sample_packets)}, "event_count": len(events), "events": events}
