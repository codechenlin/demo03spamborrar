import os
import time
import asyncio
from fastapi import FastAPI, Request, Body, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from typing import Optional

from .models import ClassificationResult, JsonEmailInput
from .security import assert_api_key
from .spamd_client import process_with_spamd
from .clamd_client import scan_raw_mime_with_clamd

LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
DEFAULT_SENSITIVITY = float(os.getenv("DEFAULT_SENSITIVITY", "5.0"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "4"))

semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

api = FastAPI(title="SpamAssassin Classification API", version="1.0.0")

def normalize_sensitivity(s: Optional[float]) -> float:
    """
    El usuario envía sensibilidad 1.0 (paranoico) a 10.0 (relajado).
    Usamos ese valor directamente como threshold en SpamAssassin.
    - 1.0 => threshold 1.0 (muy estricto)
    - 10.0 => threshold 10.0 (muy permisivo)
    """
    if s is None:
        return DEFAULT_SENSITIVITY
    if s < 1.0 or s > 10.0:
        raise HTTPException(status_code=422, detail="Sensitivity must be between 1.0 and 10.0")
    return round(s, 2)

@api.get("/health")
async def health():
    return {"status": "ok"}

@api.post("/classify/mime", response_model=ClassificationResult)
async def classify_mime(
    request: Request,
    raw_mime: str = Body(..., media_type="text/plain"),
    sensitivity: float = Body(..., embed=True),
    return_details: bool = Body(default=True, embed=True),
    clamav_scan: bool = Body(default=False, embed=True),
):
    assert_api_key(request)
    threshold = normalize_sensitivity(sensitivity)

    start = time.time()
    # Cola implícita: si hay demasiadas solicitudes, estas esperan en el semaphore
    async with semaphore:
        virusDetected = False
        if clamav_scan:
            virusDetected = scan_raw_mime_with_clamd(raw_mime)

        score, applied_threshold, headers, details = process_with_spamd(raw_mime, threshold)

        is_spam = score >= applied_threshold
        # Construir headers de salida coherentes
        out_headers = {
            "X-Spam-Status": f"{'Yes' if is_spam else 'No'}, score={score} required={applied_threshold}",
            "X-Spam-Score": f"{score}",
            "X-Spam-Threshold": f"{applied_threshold}",
        }
        # Si SpamAssassin añadió otros headers, los incorporamos
        out_headers.update(headers)

        processingMs = int((time.time() - start) * 1000)

        return ClassificationResult(
            isSpam=is_spam,
            score=score,
            sensitivity=threshold,
            thresholdApplied=applied_threshold,
            details=[{"rule": k, "score": v} for k, v in (details if return_details else {}).items()] if return_details else [],
            virusDetected=virusDetected if clamav_scan else None,
            headers=out_headers,
            processingMs=processingMs,
        )

@api.post("/classify/json", response_model=ClassificationResult)
async def classify_json(request: Request, payload: JsonEmailInput):
    assert_api_key(request)
    threshold = normalize_sensitivity(payload.sensitivity)

    start = time.time()
    async with semaphore:
        virusDetected = False
        if payload.clamav_scan:
            virusDetected = scan_raw_mime_with_clamd(payload.raw_mime)

        score, applied_threshold, headers, details = process_with_spamd(payload.raw_mime, threshold)

        is_spam = score >= applied_threshold
        out_headers = {
            "X-Spam-Status": f"{'Yes' if is_spam else 'No'}, score={score} required={applied_threshold}",
            "X-Spam-Score": f"{score}",
            "X-Spam-Threshold": f"{applied_threshold}",
        }
        out_headers.update(headers)
        processingMs = int((time.time() - start) * 1000)

        return ClassificationResult(
            isSpam=is_spam,
            score=score,
            sensitivity=threshold,
            thresholdApplied=applied_threshold,
            details=[{"rule": k, "score": v} for k, v in (details if payload.return_details else {}).items()] if payload.return_details else [],
            virusDetected=virusDetected if payload.clamav_scan else None,
            headers=out_headers,
            processingMs=processingMs,
        )
