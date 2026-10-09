from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    timestamp: Optional[datetime]
    event_id: Optional[int]
    channel: Optional[str]
    computer: Optional[str]
    provider: Optional[str]
    record_id: Optional[int]
    level: Optional[str]
    user: Optional[str]
    event_data: dict
    raw_xml: str
    evidence_id: Optional[str] = None
    case_id: Optional[str] = None
    db_id: Optional[int] = None