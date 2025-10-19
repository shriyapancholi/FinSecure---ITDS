# threat_detection/responses_schema.py
from datetime import datetime
from pydantic import BaseModel
from typing import Dict, Any

class ResponseOut(BaseModel):
    id: int
    user_id: str
    rule: str
    severity: str
    timestamp: datetime
    details: Dict[str, Any]

    class Config:
        orm_mode = True