# Endpoints

## Autenticación
- Enviar header `X-Api-Key: <tu_api_key>`. Respuesta 401 si falta o es inválida.

## POST /classify/mime
- Content-Type: `text/plain`
- Body:
  - `raw_mime`: string (RFC 822 completo)
  - `sensitivity`: float (1.0 a 10.0, obligatorio)
  - `return_details`: bool (default true)
  - `clamav_scan`: bool (default false)
- Respuesta: objeto JSON con `isSpam`, `score`, `sensitivity`, `thresholdApplied`, `details`, `virusDetected`, `headers`, `processingMs`.

## POST /classify/json
- Content-Type: `application/json`
- Body:
  ```json
  {
    "raw_mime": "<mensaje RFC 822>",
    "sensitivity": 5.0,
    "return_details": true,
    "clamav_scan": false
  }
