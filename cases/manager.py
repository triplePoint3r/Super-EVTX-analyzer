import sqlite3
import uuid
from evidence.metadata import EvidenceMetadata
from datetime import datetime
from pathlib import Path
from typing import Optional


class CaseManager:
    """
    Manage forensic investigation cases.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.connection = None

    def connect(self):
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection = sqlite3.connect(
            self.db_path
        )
        self.connection.execute("PRAGMA foreign_keys = ON")

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def create_tables(self):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                original_path TEXT NOT NULL,
                acquired_path TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                modified_at TEXT NOT NULL,
                accessed_at TEXT NOT NULL,
                integrity_verified INTEGER NOT NULL,
                FOREIGN KEY (case_id)
                    REFERENCES cases(case_id)
            )
        """)

        self.connection.commit()

    def create_case(
        self,
        name: str,
        description: str = ""
    ) -> str:

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        case_id = str(uuid.uuid4())

        created_at = datetime.now().astimezone().isoformat()

        self.connection.execute(
            """
            INSERT INTO cases (
                case_id,
                name,
                description,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                case_id,
                name,
                description,
                "open",
                created_at
            )
        )

        self.connection.commit()

        return case_id

    def get_case(self, case_id: str):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            """
            SELECT
                case_id,
                name,
                description,
                status,
                created_at
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,)
        )

        return cursor.fetchone()

    def list_cases(self):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            """
            SELECT
                case_id,
                name,
                description,
                status,
                created_at
            FROM cases
            ORDER BY created_at DESC
            """
        )

        return cursor.fetchall()

    def update_status(
        self,
        case_id: str,
        status: str
    ):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        allowed_statuses = {
            "open",
            "closed",
            "archived"
        }

        if status not in allowed_statuses:
            raise ValueError(
                f"Invalid case status: {status}"
            )

        self.connection.execute(
            """
            UPDATE cases
            SET status = ?
            WHERE case_id = ?
            """,
            (
                status,
                case_id
            )
        )

        self.connection.commit()

    def add_evidence(self,case_id: str,metadata: EvidenceMetadata) -> str:
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        if self.get_case(case_id) is None:
            raise ValueError(
            f"Case not found: {case_id}"
        )

        evidence_id = str(uuid.uuid4())

        self.connection.execute(
            """
            INSERT INTO evidence (
            evidence_id,
            case_id,
            filename,
            original_path,
            acquired_path,
            size,
            sha256,
            created_at,
            modified_at,
            accessed_at,
            integrity_verified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                evidence_id,
                case_id,
                metadata.filename,
                metadata.original_path,
                metadata.acquired_path,
                metadata.size,
                metadata.sha256,
                metadata.created_at,
                metadata.modified_at,
                metadata.accessed_at,
                int(metadata.integrity_verified),
            )
        )

        self.connection.commit()

        return evidence_id

    def get_case_evidence(self,case_id: str):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            """
            SELECT
                evidence_id,
                filename,
                original_path,
                acquired_path,
                size,
                sha256,
                created_at,
                modified_at,
                accessed_at,
                integrity_verified
            FROM evidence
            WHERE case_id = ?
            ORDER BY created_at
            """,(case_id,)
        )

        return cursor.fetchall()