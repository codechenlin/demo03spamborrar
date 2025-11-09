import os
import socket

ENABLE_CLAMAV = os.getenv("ENABLE_CLAMAV", "false").lower() == "true"
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "localhost")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT") or "3310")

def scan_raw_mime_with_clamd(raw_mime: str) -> bool:
    """
    Escanea el mensaje completo con clamd. Si detecta virus, devuelve True.
    Se usa el comando INSTREAM del protocolo clamd.
    """
    if not ENABLE_CLAMAV:
        return False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((CLAMAV_HOST, CLAMAV_PORT))
    try:
        s.sendall(b"zINSTREAM\0")
        data = raw_mime.encode("utf-8", errors="ignore")
        # clamd espera tamaño de chunk (uint32) seguido del chunk
        # enviamos en trozos razonables
        idx = 0
        while idx < len(data):
            chunk = data[idx:idx+8192]
            s.sendall(len(chunk).to_bytes(4, "big") + chunk)
            idx += len(chunk)
        s.sendall((0).to_bytes(4, "big"))
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        # Ejemplos: "stream: OK", "stream: Eicar-Test-Signature FOUND"
        return "FOUND" in resp
    finally:
        s.close()
