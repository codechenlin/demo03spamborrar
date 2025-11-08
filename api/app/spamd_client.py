import os
import socket
import time
from typing import Tuple, Dict

SPAMD_HOST = os.getenv("SPAMD_HOST", "spamd")
SPAMD_PORT = int(os.getenv("SPAMD_PORT", "783"))
REQUEST_TIMEOUT_MS = int(os.getenv("REQUEST_TIMEOUT_MS", "12000"))

def _build_spamc_request(raw_mime: str, threshold: float) -> bytes:
    # Protocolo spamd (inspirado en spamc): enviamos headers incluyendo threshold dinámico
    # Usamos a modo simple el comando "PROCESS" con headers personalizados.
    # Nota: SpamAssassin respeta 'required_score' si se pasa en el mensaje como header 'X-Spam-Threshold'.
    # Para mayor compatibilidad, añadimos 'X-Spam-Threshold' y también 'required_score' en el cuerpo.
    # Muchos setups usan 'spamd' que evalúa el mensaje; custom headers ayudan a reglas locales.
    headers = [
        "PROCESS SPAMC/1.2",
        f"Content-length: {len(raw_mime.encode('utf-8'))}",
        f"X-Spam-Threshold: {threshold}",
    ]
    request = "\r\n".join(headers) + "\r\n\r\n" + raw_mime
    return request.encode("utf-8")

def _parse_spamd_response(data: bytes) -> Tuple[float, float, Dict[str, str], Dict[str, float]]:
    # Parse básico del resultado de spamd.
    # Buscamos líneas como: "Spam: True ; 6.2 / 5.0"
    # Y cabeceras 'X-Spam-Status', 'X-Spam-Score'. Si el servidor las inserta, las devolvemos.
    text = data.decode("utf-8", errors="ignore")
    score = 0.0
    threshold = 5.0
    headers: Dict[str, str] = {}
    rule_details: Dict[str, float] = {}

    for line in text.splitlines():
        if line.lower().startswith("spam:"):
            # Ej: "Spam: True ; 6.2 / 5.0"
            try:
                parts = line.split(";")
                right = parts[1].strip()
                nums = right.split("/")
                score = float(nums[0].strip())
                threshold = float(nums[1].strip())
            except Exception:
                pass
        elif line.lower().startswith("x-spam-status:"):
            headers["X-Spam-Status"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("x-spam-score:"):
            headers["X-Spam-Score"] = line.split(":", 1)[1].strip()
        elif line.strip().startswith("(") and line.strip().endswith(")"):
            # Algunas respuestas listan reglas como "(RULE1=1.5 RULE2=0.2)"
            inner = line.strip()[1:-1]
            for token in inner.split():
                if "=" in token:
                    name, val = token.split("=", 1)
                    try:
                        rule_details[name] = float(val)
                    except Exception:
                        pass

    return score, threshold, headers, rule_details

def process_with_spamd(raw_mime: str, threshold: float) -> Tuple[float, float, Dict[str, str], Dict[str, float]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(REQUEST_TIMEOUT_MS / 1000.0)
    start = time.time()
    try:
        s.connect((SPAMD_HOST, SPAMD_PORT))
        s.sendall(_build_spamc_request(raw_mime, threshold))
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        score, applied_threshold, headers, details = _parse_spamd_response(data)
        return score, applied_threshold, headers, details
    finally:
        s.close()
