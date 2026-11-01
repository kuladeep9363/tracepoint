"""Bounded streaming writes for uploaded capture files."""

from fastapi import HTTPException, UploadFile

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


async def save_upload(upload: UploadFile, destination: str, max_bytes: int) -> int:
    """Stream an upload to disk without trusting its declared Content-Length."""
    total = 0
    try:
        with open(destination, "wb") as output:
            while chunk := await upload.read(CHUNK_SIZE):
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File is too large. The maximum upload size is {max_bytes // (1024 * 1024)} MB.",
                    )
                output.write(chunk)
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not save the uploaded file.") from exc

    if total == 0:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    return total
