from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str

    timestamp: Optional[datetime]
    event_id: Optional[int]
    record_id: Optional[int]
    channel: Optional[str]
    computer: Optional[str]
    user: Optional[str]

    evidence_id: Optional[str]
    case_id: Optional[str]

    mitre_technique: Optional[str] = None
    db_id: Optional[int] = None