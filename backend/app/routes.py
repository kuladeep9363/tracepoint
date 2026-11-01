from pathlib import Path
import tempfile

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.parser import CaptureParseError, parse_capture
from app.serializers import capture_to_json
from app.uploads import MAX_UPLOAD_BYTES, save_upload

router = APIRouter()
ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}


@router.post("/pcap/parse", summary="Parse an uploaded PCAP capture")
async def parse_pcap(file: UploadFile = File(...)) -> dict:
    """Save, parse, and normalize a packet capture, then remove the temp file."""
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type. Upload a .pcap, .pcapng, or .cap file.",
        )

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="tracepoint-", suffix=suffix, delete=False) as temp_file:
            temp_path = temp_file.name
        await save_upload(file, temp_path, MAX_UPLOAD_BYTES)
        parsed_capture = parse_capture(temp_path)
        display_name = (file.filename or "capture").replace("\\", "/")
        return capture_to_json(parsed_capture, filename=Path(display_name).name)
    except HTTPException:
        raise
    except CaptureParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        await file.close()
