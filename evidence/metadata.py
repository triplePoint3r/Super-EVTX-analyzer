from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class EvidenceMetadata:
    original_path: str
    acquired_path: str
    filename: str
    size: int
    sha256: str
    created_at: str
    modified_at: str
    accessed_at: str
    integrity_verified: bool