# Tracepoint packet parsing API

## Architecture

1. `routes.py` validates the filename extension and coordinates the request.
2. `uploads.py` streams the multipart file to a temporary file with a size cap.
3. `parser.py` reads classic PCAP or PCAPNG records and extracts a small set of packet metadata (including best-effort MAC/ARP, DNS, DHCP, TCP sequence, and HTTP start-line metadata; it does not retain HTTP bodies).
4. `serializers.py` maps parser records to a stable JSON response. The temporary file is removed after the request, including on errors.

The parser keeps malformed frames out of the packet list and reports their count. It does not decode application payloads. The DNS label is based only on port 53.

## Run locally

From the `backend` directory:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API listens at `http://127.0.0.1:8000`; interactive API docs are at `/docs`. Development CORS origins for ports 3000 and 5173 are enabled by default. Set `CORS_ORIGINS` to a comma-separated list of exact frontend origins when deploying.

## Frontend request

Send the file as multipart form data. The field name is `file`:

```js
const body = new FormData();
body.append("file", selectedFile);

const response = await fetch("http://127.0.0.1:8000/api/pcap/parse", {
  method: "POST",
  body,
});

const result = await response.json();
if (!response.ok) throw new Error(result.detail ?? "Capture parsing failed");
```

Do not set the `Content-Type` header manually; the browser adds the multipart boundary. The request size limit is 100 MiB and the parser currently caps a capture at 100,000 packets.

## Stage 2: analysis events and findings

The event stage normalizes packets and then groups TCP handshakes, DNS exchanges, and only HTTP requests that have a matching response on the reversed connection (within 30 seconds). Every pair is a separate event; adjacent HTTP packets are never merged by flow alone. Grouped rows carry packet numbers and a packet count.

Every row has a `classification`: `likely fault`, `possible attack`, or `needs review`, plus a structured `explanation` with `what_this_means`, `why_it_was_flagged`, and `suggested_response`. Fault rules include TCP resets/retransmissions, DNS error or slow responses, slow HTTP responses, duplicate IP claims, ARP address conflicts, and ICMP fragmentation-needed MTU reports. Attack heuristics include port scans (10 or more destination ports in a 10-second bucket), DoS/DDoS bursts (100 or more packets to one destination/port in 5 seconds; DDoS uses 10 or more source IPs), conflicting ARP replies for one IP, multiple DHCP offers from distinct server identities for one transaction, and inconsistent DNS answers from distinct resolvers for one name within a minute. Heuristics are review signals and may also match normal scanning, failover, CDN, or flash-crowd behavior.

The analysis is intentionally metadata-only. It does not infer directory scans from encrypted HTTPS, inspect HTTP bodies, or claim certainty about intent. HTTP request/response grouping depends on a parsed HTTP start line in visible TCP payload; HTTPS is not treated as HTTP. DNS matching uses reversed endpoint tuple and, where available, DNS transaction ID.

### Event endpoints

- `POST /api/events/analyze` accepts the Stage 1 JSON object (`{ "capture": ..., "packets": [...] }`) and returns `{ "capture": ..., "event_count": ..., "events": [...] }`.
- `POST /api/pcap/analyze` accepts the same multipart upload as `/api/pcap/parse`, then parses and returns events in one request.
- `GET /api/events/demo` returns a deterministic sample response that can be opened directly in a browser.

### Frontend row schema

Each `events[]` row has this shape:

```json
{
  "id": "evt-000001",
  "s_no": 1,
  "time": "2026-11-01T08:15:30.000000Z",
  "source": "192.168.1.20:51824",
  "destination": "93.184.216.34:443",
  "protocol": "TCP",
  "summary": "TCP 3-way handshake",
  "severity": "low",
  "color": "teal",
  "classification": "needs review",
  "explanation": {
    "what_this_means": "A TCP connection was established successfully.",
    "why_it_was_flagged": "The capture contains the opening request, server reply, and final confirmation.",
    "suggested_response": ["No action is needed unless this connection is unexpected."],
    "detection_assessment": "Normal connection setup; no attack is implied."
  },
  "details": { "packet_numbers": [1, 2, 3], "packet_count": 3 }
}
```

`severity` is `info`, `low`, `medium`, or `high`; `color` is a presentation token (`neutral`, `teal`, `amber`, or `red`). Modal text comes from `explanation`; packet numbers and grouped evidence remain in `details`.

The demo endpoint returns a 245-packet capture with five event rows: two separate scan directions (odd and even packet numbers from `1` to `238`), TCP handshake (`239–241`), DNS exchange (`242–243`), and HTTP traffic (`244–245`). Each scan row’s `details.packet_numbers` contains the complete sorted packet list; the frontend provides it through the packet-number ellipsis.

### Run and preview locally on Windows

From PowerShell, run these commands:

```powershell
cd C:\Users\write\cyber-hackathon-codex\backend
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/api/events/demo** in a browser to see the generated five-row JSON example, including separate scan directions and the matched HTTP request/response pair. Confirm every row contains a classification, an explanation with the three beginner-friendly keys, and packet numbers under `details`. Open **http://127.0.0.1:8000/docs** to inspect and call the JSON analysis or PCAP upload endpoints. In a capture with more than three related packets, the modal and table evidence should retain the complete packet number list.

## Example response

```json
{
  "capture": {
    "filename": "sample.pcap",
    "packet_count": 2,
    "skipped_packet_count": 0
  },
  "packets": [
    {
      "number": 1,
      "timestamp": "2026-11-01T08:15:30.125000Z",
      "source_ip": "192.168.1.20",
      "source_port": 51824,
      "destination_ip": "93.184.216.34",
      "destination_port": 443,
      "protocol": "TCP",
      "description": "TCP SYN",
      "flags": ["SYN"],
      "labels": []
    },
    {
      "number": 2,
      "timestamp": "2026-11-01T08:15:30.130000Z",
      "source_ip": "192.168.1.20",
      "source_port": 53001,
      "destination_ip": "192.168.1.1",
      "destination_port": 53,
      "protocol": "UDP",
      "description": "UDP datagram · DNS traffic",
      "flags": [],
      "labels": ["dns"]
    }
  ]
}
```
