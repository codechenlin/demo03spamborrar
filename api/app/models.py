from pydantic import BaseModel, Field
from typing import Optional, List, Dict

class ClassificationResult(BaseModel):
    isSpam: bool
    score: float
    sensitivity: float
    thresholdApplied: float
    details: List[Dict[str, float]]  # [{'RULE_NAME': score_contrib}, ...]
    virusDetected: Optional[bool] = None
    headers: Dict[str, str]
    processingMs: int

class JsonEmailInput(BaseModel):
    raw_mime: str = Field(..., description="Mensaje RFC 822 completo (MIME) como string")
    sensitivity: float = Field(..., ge=1.0, le=10.0, description="1.0 paranoico, 10.0 relajado")
    return_details: bool = True
    clamav_scan: bool = False
