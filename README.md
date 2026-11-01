# Tracepoint

Tracepoint is a clean, minimal packet-analysis web app that turns raw PCAP captures into readable event rows. It is built for beginners and students who may find Wireshark overwhelming, so it shows only the information they need and hides deep packet-level noise by default.

## What it does

Tracepoint accepts a packet capture file and converts it into a simplified analysis view similar to Wireshark, but easier to read.

It can:
- accept `.pcap`, `.pcapng`, and `.cap` files
- parse packet data into structured JSON
- group related packets into higher-level events
- display event rows in a table
- open a centered details modal for each event
- filter results by protocol, severity, source IP, destination IP, and time range
- search visible events
- export the current table view as CSV

## Why the interface is grouped and simplified

Packet captures can be noisy and difficult to read, especially for new users. Tracepoint groups related traffic into compact event rows so the interface stays readable and focused.

This design helps users quickly understand:
- what happened
- which packets belong together
- whether something looks like a normal fault or a possible attack
- what they should check next

The goal is to keep the analysis useful without exposing beginners to too much technical detail at once.

## Main features

### Upload and analysis
Users can drag and drop a capture file into the upload area or click the upload zone to open the file picker. After upload, the capture is sent to the backend for parsing and analysis.

### Grouped event table
The frontend shows analyzed traffic as compact event rows instead of raw packet noise. Related packets are grouped into a single event where appropriate, such as:
- TCP 3-way handshakes
- DNS query and response pairs
- HTTP request and response pairs
- possible scan bursts
- possible DoS / DDoS bursts

### Event details modal
Clicking an event row opens a centered modal with useful context such as:
- event title
- severity
- protocol
- time
- source and destination
- packet count
- packet numbers or packet range
- grouped context
- explanation and suggested response

### Filters and search
The event list can be filtered using:
- protocol
- severity
- source IP
- destination IP
- time range
- search text

### CSV export
The visible rows can be exported as a CSV file for sharing or later review.

## How it works

Tracepoint follows a simple pipeline:

1. The user uploads a PCAP file.
2. The backend parses the capture into normalized packet data.
3. Packets are grouped into events.
4. The analysis layer classifies the event as a likely fault, possible attack, or needs review.
5. The frontend displays the results in a readable table.
6. Clicking a row opens a modal with details and suggested action.

## Faults vs attacks

Tracepoint is designed to distinguish between:
- **faults** such as TCP retransmissions, resets, DNS failures, duplicate IPs, ARP conflicts, MTU mismatches, and unusual delays
- **possible attacks** such as port scans, ARP spoofing, DNS hijacking, rogue DHCP servers, DoS, and DDoS

Each finding includes a short explanation and a practical next step.

## Project structure

A typical layout is:

```text
.
├── index.html
├── styles.css
├── app.js
├── README.md
└── backend/
    ├── main.py
    ├── parser.py
    ├── analyzer.py
    └── requirements.txt
```

## Setup

### 1. Clone or download the project
Make sure the frontend and backend files are available locally.

### 2. Install dependencies

If the project uses a Python backend, install the backend requirements:

```bash
pip install -r backend/requirements.txt
```

If the frontend is served as a static site, no additional build step is required unless a bundler is being used.

### 3. Configure the backend URL

If the frontend talks to a local backend, update the API base URL in the frontend code if needed.

Common example:

```text
http://127.0.0.1:8000
```

## Run the project

### Backend
Start the Python FastAPI backend:

```bash
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend
Serve the frontend with any local static server. One simple option is:

```bash
python -m http.server 5173
```

Then open:

```text
http://127.0.0.1:5173
```

If the frontend is already wired into a dev server, use that server instead.

## How to use

1. Open the app in a browser.
2. Drop a PCAP file into the upload area or click the upload zone.
3. Wait for the capture to be processed.
4. Review the grouped event rows in the table.
5. Use the filters and search bar to narrow results.
6. Click any row to open the details modal.
7. Export the visible rows as CSV if needed.

## File format support

Supported input formats:
- `.pcap`
- `.pcapng`
- `.cap`

## Notes

- The app is intended for lab, sample, or authorized packet captures only.
- The analysis logic is deliberately simplified for readability and hackathon use.
- The output is designed to be understandable for beginners while still being useful for inspection and demo purposes.

## Tech stack

- HTML
- CSS
- JavaScript
- Python
- FastAPI
- PCAP parsing and analysis libraries as used in the backend

## License

Add a license here if needed for the submission or repository.

## Demo

Add the demo video link here if the hackathon submission requires one.
