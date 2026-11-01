# Tracepoint frontend preview

## Frontend architecture

- `index.html` contains the large upload hero, event table, filter bar, CSV export button, and centered details modal.
- `app.js` handles upload requests, the demo endpoint, response rendering, search and filters, CSV export, and row details.
- `styles.css` contains the responsive styling and the shared severity/color tokens.
- The UI uses the backend event response as its data source. It does not create or modify analysis events.

The upload flow sends a selected `.pcap`, `.pcapng`, or `.cap` file as multipart field `file` to `POST /api/pcap/analyze`. For a no-file preview, the **Load demo analysis** button reads `GET /api/events/demo`. The filter bar can narrow the backend events by protocol, severity, source, destination, time range, or a general search. **Export CSV** downloads the rows currently visible after all filters.

## Run locally on Windows

Use two PowerShell terminals.

**Terminal 1 — start FastAPI** (install dependencies first if this environment has not been set up):

```powershell
cd C:\Users\write\cyber-hackathon-codex\backend
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

If the backend virtual environment already exists, start it with:

```powershell
cd C:\Users\write\cyber-hackathon-codex\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

**Terminal 2 — serve the frontend files**:

```powershell
cd C:\Users\write\cyber-hackathon-codex
py -m http.server 5173
```

Open **http://127.0.0.1:5173**. Confirm the first view has only the large centered upload hero, with its heading on one line. Click **Load demo analysis** to check that the page scrolls into five rows: two separate scan rows, a handshake, DNS, and HTTP. The scan rows show an ellipsis in Packet No.; hover the ellipsis after clicking it to see the full packet list. Try the filters, open and dismiss a modal, then export the visible rows as CSV. For an actual capture, click anywhere in the drop area or use **Browse files**.

The demo endpoint itself is also viewable as JSON at **http://127.0.0.1:8000/api/events/demo**. The API documentation at **http://127.0.0.1:8000/docs** lets you inspect and call the backend routes.

## Preview layout

The landing view centers a large drag-and-drop upload hero, scaled to 90% overall with a one-line headline. The empty analysis hint sits lower on the page so the initial view stays focused on the hero. After upload, the page scrolls to the grouped event rows. S. No. and Packet No. sit side by side; groups of more than three packets use a clickable ellipsis that reveals their complete packet-number list while hovered. Reciprocal port scans remain separate rows. The filter bar narrows rows by protocol, severity, source/destination IP, time range, and search. Clicking a row opens a centered modal; click outside, use the close button, or press Escape to dismiss it. The modal includes protocol context, packet group details, detection reasoning, and response suggestions where supported. The HTTP modal displays full request/response text when the API provides it; the current parser does not yet provide HTTP payload text. Directory scans cannot be represented until the backend includes URL/path metadata and emits those events.

Event colors are mapped for quick scanning: neutral for ordinary traffic, teal for handshakes, purple for DNS, cyan for HTTP, amber for possible scans, and red for possible DoS/DDoS or high-severity activity. **Export CSV** downloads the currently filtered rows, including compact packet ranges.

## Frontend hosting link

**Local preview only:** http://127.0.0.1:5173 (after running the frontend command above). No hosted frontend deployment is configured yet.
