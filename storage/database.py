import sqlite3
from pathlib import Path
from typing import Iterable

from models.event import Event


class Database:
    """
    SQLite storage for forensic events.
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
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA temp_store = MEMORY")
        self.connection.execute("PRAGMA cache_size = -64000")

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _ensure_column(self, table: str, column: str, definition: str):
        """Add a compatible column when opening a database created by an older version."""
        columns = {
            row[1]
            for row in self.connection.execute(f"PRAGMA table_info({table})")
        }
        if column not in columns:
            self.connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
            )

    def create_tables(self):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_id INTEGER,
                channel TEXT,
                computer TEXT,
                provider TEXT,
                record_id INTEGER,
                level TEXT,
                user TEXT,
                event_data TEXT,
                raw_xml TEXT,
                evidence_id TEXT,
                case_id TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
                    ON DELETE RESTRICT,
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
                    ON DELETE RESTRICT
            )
        """)

        self._ensure_column("events", "case_id", "TEXT")
        self._ensure_column("events", "evidence_id", "TEXT")

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_event_id
            ON events(event_id)
        """)

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_channel
            ON events(channel)
        """)

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_user
            ON events(user)
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                timestamp TEXT,
                event_id INTEGER,
                channel TEXT,
                computer TEXT,
                user TEXT,
                evidence_id TEXT,
                case_id TEXT,
                mitre_technique TEXT,
                primary_event_id INTEGER,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
                    ON DELETE RESTRICT,
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
                    ON DELETE SET NULL,
                FOREIGN KEY (primary_event_id) REFERENCES events(id)
                    ON DELETE SET NULL
            )
        """)

        self._ensure_column("findings", "primary_event_id", "INTEGER")

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS correlations (
                correlation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                user TEXT,
                description TEXT,
                case_id TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                anomaly_id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                event_id INTEGER,
                count INTEGER,
                description TEXT,
                case_id TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS case_risk (
                case_id TEXT PRIMARY KEY,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_id INTEGER,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE (case_id, type, value),
                FOREIGN KEY (case_id)
                    REFERENCES cases(case_id)
            )
        """)

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_iocs_case
            ON iocs(case_id)
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS finding_mitre (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                technique_id TEXT NOT NULL,
                technique_name TEXT,
                FOREIGN KEY (finding_id)
                REFERENCES findings(finding_id)
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS finding_events (
                finding_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                relationship TEXT NOT NULL DEFAULT 'detected_from',
                PRIMARY KEY (finding_id, event_id),
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS ioc_events (
                ioc_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                PRIMARY KEY (ioc_id, event_id),
                FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS correlation_events (
                correlation_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                sequence_no INTEGER NOT NULL,
                role TEXT,
                PRIMARY KEY (correlation_id, event_id),
                UNIQUE (correlation_id, sequence_no),
                FOREIGN KEY (correlation_id) REFERENCES correlations(correlation_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS anomaly_events (
                anomaly_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                PRIMARY KEY (anomaly_id, event_id),
                FOREIGN KEY (anomaly_id) REFERENCES anomalies(anomaly_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE (case_id, type, value),
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS entity_events (
                entity_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                PRIMARY KEY (entity_id, event_id),
                FOREIGN KEY (entity_id) REFERENCES entities(entity_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (event_id) REFERENCES events(id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                event_id INTEGER,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT,
                process_id TEXT,
                description TEXT,
                sha256 TEXT,
                integrity_status TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
                    ON DELETE RESTRICT,
                FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
                    ON DELETE RESTRICT,
                FOREIGN KEY (event_id) REFERENCES events(id)
                    ON DELETE RESTRICT
            )
        """)

        self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_finding_mitre_finding
            ON finding_mitre(finding_id)
        """)

        for index_sql in (
            "CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_evidence ON events(evidence_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_case_timestamp ON events(case_id, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_case_event_id ON events(case_id, event_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_case_timestamp_id ON events(case_id, timestamp, id)",
            "CREATE INDEX IF NOT EXISTS idx_events_case_channel_timestamp ON events(case_id, channel, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_case_user_timestamp ON events(case_id, user, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_case_evidence ON events(case_id, evidence_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_primary_event ON findings(primary_event_id)",
            "CREATE INDEX IF NOT EXISTS idx_finding_events_event ON finding_events(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_events_event ON ioc_events(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_correlation_events_event ON correlation_events(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_anomaly_events_event ON anomaly_events(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_entity_events_event ON entity_events(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_custody_case_time ON chain_of_custody(case_id, timestamp)",
        ):
            self.connection.execute(index_sql)

        self.connection.execute("""
            CREATE TRIGGER IF NOT EXISTS custody_no_update
            BEFORE UPDATE ON chain_of_custody
            BEGIN
                SELECT RAISE(ABORT, 'chain_of_custody is append-only');
            END
        """)
        self.connection.execute("""
            CREATE TRIGGER IF NOT EXISTS custody_no_delete
            BEFORE DELETE ON chain_of_custody
            BEGIN
                SELECT RAISE(ABORT, 'chain_of_custody is append-only');
            END
        """)

        self.connection.commit()

    def insert_event(
    self,
    event: Event,
    case_id: str | None = None
):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        import json

        timestamp = None

        if event.timestamp is not None:
            timestamp = event.timestamp.isoformat()

        event_data = json.dumps(
            event.event_data,
            ensure_ascii=False
        )

        cursor = self.connection.execute(
            """
            INSERT INTO events (
                timestamp,
                event_id,
                channel,
                computer,
                provider,
                record_id,
                level,
                user,
                event_data,
                raw_xml,
                evidence_id,
                case_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event.event_id,
                event.channel,
                event.computer,
                event.provider,
                event.record_id,
                event.level,
                event.user,
                event_data,
                event.raw_xml,
                event.evidence_id,
                case_id if case_id is not None else event.case_id,
            )
        )
        event.db_id = cursor.lastrowid

    def count_events(self) -> int:

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            "SELECT COUNT(*) FROM events"
        )

        return cursor.fetchone()[0]

    def get_event(self, event_id: int):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            """
            SELECT
                id,
                timestamp,
                event_id,
                channel,
                computer,
                provider,
                record_id,
                level,
                user,
                event_data,
                raw_xml,
                evidence_id
            FROM events
            WHERE id = ?
            """,
            (event_id,)
        )

        return cursor.fetchone()

    def clear_events(self):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        self.connection.execute(
            "DELETE FROM events"
        )

        self.connection.commit()

    def count_events_for_evidence(
    self,
    case_id: str,
    evidence_id: str,
    ) -> int:
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        row = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE case_id = ?
            AND evidence_id = ?
            """,
            (case_id, evidence_id),
        ).fetchone()

        return row[0]
    
    def evidence_has_custody_action(
        self,
        case_id: str,
        evidence_id: str,
        action: str,
    ) -> bool:
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        row = self.connection.execute(
            """
            SELECT 1
            FROM chain_of_custody
            WHERE case_id = ?
            AND evidence_id = ?
            AND action = ?
            LIMIT 1
            """,
            (case_id, evidence_id, action),
        ).fetchone()

        return row is not None

    def insert_events(
        self,
        events: Iterable[Event],
        case_id: str | None = None,
        commit: bool = True,
    ) -> int:
        """Insert a batch with executemany instead of one SQL call per event."""
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        import json

        batch = list(events)
        if not batch:
            return 0

        values = []
        for event in batch:
            timestamp = event.timestamp.isoformat() if event.timestamp is not None else None
            values.append((
                timestamp, event.event_id, event.channel, event.computer,
                event.provider, event.record_id, event.level, event.user,
                json.dumps(event.event_data, ensure_ascii=False), event.raw_xml,
                event.evidence_id, case_id if case_id is not None else event.case_id,
            ))

        try:
            # Reserve the write lock before deriving IDs so event.db_id stays aligned
            # with SQLite IDs used by finding/event relationship tables.
            if not self.connection.in_transaction:
                self.connection.execute("BEGIN IMMEDIATE")
            current_max = self.connection.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            sequence = self.connection.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'events'"
            ).fetchone()
            sequence_max = sequence[0] if sequence else 0
            first_id = max(current_max, sequence_max) + 1
            self.connection.executemany(
                """INSERT INTO events (
                    timestamp, event_id, channel, computer, provider, record_id,
                    level, user, event_data, raw_xml, evidence_id, case_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
            for offset, event in enumerate(batch):
                event.db_id = first_id + offset
            if commit:
                self.connection.commit()
        except Exception:
            if commit:
                self.connection.rollback()
            raise
        return len(batch)

    def _resolve_event_db_id(
        self,
        event_id: int | None,
        evidence_id: str | None = None,
        record_id: int | None = None,
        case_id: str | None = None,
    ) -> int | None:
        if event_id is None and record_id is None:
            return None

        clauses = []
        values = []
        if record_id is not None:
            clauses.append("record_id = ?")
            values.append(record_id)
        if event_id is not None:
            clauses.append("event_id = ?")
            values.append(event_id)
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            values.append(evidence_id)
        if case_id is not None:
            clauses.append("case_id = ?")
            values.append(case_id)

        query = (
            "SELECT id FROM events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY id LIMIT 1"
        )
        row = self.connection.execute(query, values).fetchone()
        return row[0] if row else None

    def insert_finding(self, finding, commit: bool = True):

        if self.connection is None:
            raise RuntimeError("Database is not connected")

        timestamp = None

        if finding.timestamp is not None:
            timestamp = finding.timestamp.isoformat()

        primary_event_id = self._resolve_event_db_id(
            finding.event_id,
            evidence_id=finding.evidence_id,
            record_id=getattr(finding, "record_id", None),
            case_id=finding.case_id,
        )

        self.connection.execute(
            """
            INSERT INTO findings (
                rule_id,
                title,
                description,
                severity,
                timestamp,
                event_id,
                channel,
                computer,
                user,
                evidence_id,
                case_id,
                mitre_technique,
                primary_event_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.rule_id,
                finding.title,
                finding.description,
                finding.severity,
                timestamp,
                finding.event_id,
                finding.channel,
                finding.computer,
                finding.user,
                finding.evidence_id,
                finding.case_id,
                finding.mitre_technique,
                primary_event_id,
            )
        )
        finding_id = self.connection.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]
        finding.db_id = finding_id

        if primary_event_id is not None:
            self.connection.execute(
                "INSERT OR IGNORE INTO finding_events "
                "(finding_id, event_id) VALUES (?, ?)",
                (finding_id, primary_event_id),
            )

        if commit:
            self.connection.commit()

        return finding_id

    def insert_findings(self, findings, commit: bool = True):
        finding_ids = []

        for finding in findings:
            finding_ids.append(self.insert_finding(finding, commit=False))

        if commit:
            self.connection.commit()

        return finding_ids

    def insert_correlation(
    self,
    correlation_type: str,
    user: str | None = None,
    description: str | None = None,
    case_id: str | None = None,
        events: Iterable[Event] | None = None,
    event_roles: Iterable[tuple[Event, str]] | None = None,
    commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute("""
            INSERT INTO correlations (
                type,
                user,
                description,
                case_id
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                correlation_type,
                user,
                description,
                case_id,
            )
        )

        correlation_id = cursor.lastrowid
        if events:
            roles_by_id = {
                event.db_id: role
                for event, role in (event_roles or [])
                if event.db_id is not None
            }
            for sequence_no, event in enumerate(events):
                if event.db_id is not None:
                    self.connection.execute(
                        "INSERT OR IGNORE INTO correlation_events "
                        "(correlation_id, event_id, sequence_no, role) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            correlation_id,
                            event.db_id,
                            sequence_no,
                            roles_by_id.get(event.db_id),
                        ),
                    )
        if commit:
            self.connection.commit()
        return correlation_id

    def insert_anomaly(
    self,
    anomaly_type: str,
    event_id: int | None = None,
    count: int | None = None,
    description: str | None = None,
    case_id: str | None = None,
    events: Iterable[Event] | None = None,
    commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute("""
            INSERT INTO anomalies (
                type,
                event_id,
                count,
                description,
                case_id
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                anomaly_type,
                event_id,
                count,
                description,
                case_id,
            )
        )

        anomaly_id = cursor.lastrowid
        if events:
            for event in events:
                if event.db_id is not None:
                    self.connection.execute(
                        "INSERT OR IGNORE INTO anomaly_events "
                        "(anomaly_id, event_id) VALUES (?, ?)",
                        (anomaly_id, event.db_id),
                    )
        if commit:
            self.connection.commit()
        return anomaly_id

    def save_case_risk(
    self,
    case_id: str,
    risk_score: int,
    risk_level: str,
        commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        self.connection.execute("""
            INSERT OR REPLACE INTO case_risk (
                case_id,
                risk_score,
                risk_level
            )
            VALUES (?, ?, ?)
            """,
            (
                case_id,
                risk_score,
                risk_level,
            )
        )
        if commit:
            self.connection.commit()

    def get_case_summary(self, case_id: str) -> dict:
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        case = self.connection.execute("""
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
        ).fetchone()

        if case is None:
            raise ValueError(f"Case not found: {case_id}")

        evidence_count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM evidence
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()[0]

        event_count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()[0]

        finding_count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()[0]

        correlation_count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM correlations
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()[0]

        anomaly_count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM anomalies
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()[0]

        risk = self.connection.execute(
            """
            SELECT
                risk_score,
                risk_level
            FROM case_risk
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()

        ioc_count = self.connection.execute(
            """
            SELECT COUNT(*)
            FROM iocs
            WHERE case_id = ?
            """,
            (case_id,)
        ).fetchone()[0]

        return {
            "case": {
                "case_id": case[0],
                "name": case[1],
                "description": case[2],
                "status": case[3],
                "created_at": case[4],
            },
            "evidence_count": evidence_count,
            "event_count": event_count,
            "finding_count": finding_count,
            "correlation_count": correlation_count,
            "anomaly_count": anomaly_count,
            "ioc_count": ioc_count,
            "risk_score": risk[0] if risk else 0,
            "risk_level": risk[1] if risk else "none",
        }

    def insert_ioc(
        self,
        case_id: str,
        event_id: int | None,
        ioc_type: str,
        value: str,
        commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        existing = self.connection.execute(
            "SELECT ioc_id FROM iocs WHERE case_id = ? AND type = ? AND value = ?",
            (case_id, ioc_type, value),
        ).fetchone()

        if existing is None:
            self.connection.execute("""
                INSERT INTO iocs (
                case_id,
                event_id,
                type,
                value
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    case_id,
                    event_id,
                    ioc_type,
                    value,
                ),
            )

        ioc_id = existing[0] if existing else self.connection.execute(
                "SELECT ioc_id FROM iocs WHERE case_id = ? AND type = ? AND value = ?",
                (case_id, ioc_type, value),
            ).fetchone()[0]

        if event_id is not None:
            self.connection.execute(
                "INSERT OR IGNORE INTO ioc_events (ioc_id, event_id) VALUES (?, ?)",
                (ioc_id, event_id),
            )

        if commit:
            self.connection.commit()

        return ioc_id

    def get_case_iocs(self, case_id: str):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            """
            SELECT i.ioc_id,
                   GROUP_CONCAT(ie.event_id),
                   i.type,
                   i.value
            FROM iocs i
            LEFT JOIN ioc_events ie ON ie.ioc_id = i.ioc_id
            WHERE i.case_id = ?
            GROUP BY i.ioc_id, i.type, i.value
            ORDER BY i.ioc_id
            """,
            (case_id,),
        ).fetchall()

        return cursor

    def persist_analysis_result(self, result: dict, events: Iterable[Event], case_id: str):
        """Persist one analysis result while retaining all source-event relationships."""
        events = list(events)
        with self.connection:
            pending_events = [event for event in events if event.db_id is None]
            if pending_events:
                self.insert_events(pending_events, case_id=case_id, commit=False)

            finding_ids = self.insert_findings(result.get("findings", []), commit=False)
            for finding, finding_id in zip(result.get("findings", []), finding_ids):
                if finding.mitre_technique:
                    from intelligence.mitre import MitreMapper
                    self.insert_finding_mitre(
                        finding_id,
                        finding.mitre_technique,
                        MitreMapper.get_technique_name(finding.rule_id),
                        commit=False,
                    )

            correlation_ids = []
            for correlation in result.get("correlations", []):
                correlation_ids.append(self.insert_correlation(
                    correlation_type=correlation["type"],
                    user=correlation.get("user"),
                    description=f"Correlation detected for user {correlation.get('user')}",
                    case_id=case_id,
                    events=correlation.get("events", []),
                    event_roles=correlation.get("event_roles", []),
                    commit=False,
                ))

            anomaly_ids = []
            for anomaly in result.get("anomalies", []):
                anomaly_ids.append(self.insert_anomaly(
                    anomaly_type=anomaly["type"],
                    event_id=anomaly.get("event_id"),
                    count=anomaly.get("count"),
                    description=anomaly.get("description"),
                    case_id=case_id,
                    events=anomaly.get("events", []),
                    commit=False,
                ))

            for ioc_result in result.get("iocs", []):
                source_event = ioc_result.get("event")
                source_id = source_event.db_id if source_event else None
                for ioc_type, values in ioc_result.get("iocs", {}).items():
                    for value in values:
                        self.insert_ioc(
                            case_id, source_id, ioc_type, str(value), commit=False
                        )

            for entity_result in result.get("entities", []):
                source_event = entity_result.get("event")
                if source_event is None or source_event.db_id is None:
                    continue
                for entity_type, values in entity_result.get("entities", {}).items():
                    normalized_type = {
                        "users": "user",
                        "computers": "computer",
                        "processes": "process",
                    }.get(entity_type, entity_type)
                    for value in values:
                        entity_id = self.insert_entity(
                            case_id, normalized_type, str(value), commit=False
                        )
                        self.link_entity_event(entity_id, source_event.db_id, commit=False)

            self.save_case_risk(
                case_id,
                result.get("risk_score", 0),
                result.get("risk_level", "none"),
                commit=False,
            )

        return {
            "finding_ids": finding_ids,
            "correlation_ids": correlation_ids,
            "anomaly_ids": anomaly_ids,
        }

    def insert_entity(
        self,
        case_id: str,
        entity_type: str,
        value: str,
        commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        row = self.connection.execute(
            "SELECT entity_id FROM entities "
            "WHERE case_id = ? AND type = ? AND value = ?",
            (case_id, entity_type, value),
        ).fetchone()

        if row is None:
            cursor = self.connection.execute(
                "INSERT INTO entities (case_id, type, value) VALUES (?, ?, ?)",
                (case_id, entity_type, value),
            )
            entity_id = cursor.lastrowid
        else:
            entity_id = row[0]

        if commit:
            self.connection.commit()

        return entity_id

    def link_entity_event(
        self,
        entity_id: int,
        event_id: int,
        commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO entity_events (entity_id, event_id) "
            "VALUES (?, ?)",
            (entity_id, event_id),
        )

        if commit:
            self.connection.commit()

        if cursor.rowcount == 0:
            return None

        return {
            "entity_id": entity_id,
            "event_id": event_id,
        }

    def link_finding_event(
        self,
        finding_id: int,
        event_id: int,
        commit: bool = False,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO finding_events "
            "(finding_id, event_id) VALUES (?, ?)",
            (finding_id, event_id),
        )

        if commit:
            self.connection.commit()

        if cursor.rowcount == 0:
            return None

        return {
            "finding_id": finding_id,
            "event_id": event_id,
        }

    def get_finding_events(self, finding_id: int):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            "SELECT event_id FROM finding_events "
            "WHERE finding_id = ? ORDER BY event_id",
            (finding_id,),
        ).fetchall()

    def get_event_iocs(self, event_id: int):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT i.ioc_id, i.case_id, i.type, i.value
            FROM iocs i
            JOIN ioc_events ie ON ie.ioc_id = i.ioc_id
            WHERE ie.event_id = ?
            ORDER BY i.ioc_id
            """,
            (event_id,),
        ).fetchall()

    def get_evidence_iocs(self, evidence_id: str):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT DISTINCT i.ioc_id, i.case_id, i.type, i.value
            FROM iocs i
            JOIN ioc_events ie ON ie.ioc_id = i.ioc_id
            JOIN events e ON e.id = ie.event_id
            WHERE e.evidence_id = ?
            ORDER BY i.ioc_id
            """,
            (evidence_id,),
        ).fetchall()

    def get_event_entities(self, event_id: int):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT e.entity_id, e.case_id, e.type, e.value
            FROM entities e
            JOIN entity_events ee ON ee.entity_id = e.entity_id
            WHERE ee.event_id = ?
            ORDER BY e.entity_id
            """,
            (event_id,),
        ).fetchall()

    def get_correlation_events(self, correlation_id: int):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT event_id, sequence_no, role
            FROM correlation_events
            WHERE correlation_id = ?
            ORDER BY sequence_no
            """,
            (correlation_id,),
        ).fetchall()

    def get_anomaly_events(self, anomaly_id: int):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            "SELECT event_id FROM anomaly_events "
            "WHERE anomaly_id = ? ORDER BY event_id",
            (anomaly_id,),
        ).fetchall()

    def insert_chain_of_custody(
        self,
        case_id: str,
        action: str,
        evidence_id: str | None = None,
        event_db_id: int | None = None,
        actor: str | None = None,
        process_id: str | None = None,
        description: str | None = None,
        sha256: str | None = None,
        integrity_status: str | None = None,
        details_json: str = "{}",
    ) -> int:
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        from datetime import datetime

        cursor = self.connection.execute(
            """
            INSERT INTO chain_of_custody (
                case_id, evidence_id, event_id, action, timestamp,
                actor, process_id, description, sha256,
                integrity_status, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                evidence_id,
                event_db_id,
                action,
                datetime.now().astimezone().isoformat(),
                actor,
                process_id,
                description,
                sha256,
                integrity_status,
                details_json,
            ),
        )
        self.connection.commit()
        return cursor.lastrowid

    def get_case_custody(self, case_id: str):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT custody_id, evidence_id, event_id, action, timestamp,
                   actor, process_id, description, sha256,
                   integrity_status, details_json
            FROM chain_of_custody
            WHERE case_id = ?
            ORDER BY custody_id
            """,
            (case_id,),
        ).fetchall()

    def get_case_findings(self, case_id: str):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT finding_id, rule_id, title, severity, timestamp,
                   event_id, primary_event_id, evidence_id, case_id
            FROM findings
            WHERE case_id = ?
            ORDER BY finding_id
            """,
            (case_id,),
        ).fetchall()

    def get_case_events(self, case_id: str):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        return self.connection.execute(
            """
            SELECT id, evidence_id, event_id, record_id, timestamp,
                   channel, computer, provider, level, user
            FROM events
            WHERE case_id = ?
            ORDER BY timestamp, id
            """,
            (case_id,),
        ).fetchall()

    def get_case_events_page(self, case_id: str, limit: int = 200, offset: int = 0):
        """Fetch a bounded timeline page; never fetch event_data/raw_xml for list views."""
        if self.connection is None:
            raise RuntimeError("Database is not connected")
        limit = max(1, min(int(limit), 2000))
        offset = max(0, int(offset))
        return self.connection.execute(
            """SELECT id, evidence_id, event_id, record_id, timestamp,
                      channel, computer, provider, level, user
               FROM events WHERE case_id = ?
               ORDER BY timestamp, id LIMIT ? OFFSET ?""",
            (case_id, limit, offset),
        ).fetchall()

    def insert_finding_mitre(
        self,
        finding_id: int,
        technique_id: str,
        technique_name: str | None = None,
        commit: bool = True,
    ):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        existing = self.connection.execute(
            "SELECT id FROM finding_mitre WHERE finding_id = ? AND technique_id = ?",
            (finding_id, technique_id),
        ).fetchone()
        if existing is not None:
            return existing[0]

        cursor = self.connection.execute(
            """
            INSERT INTO finding_mitre (
                finding_id,
                technique_id,
                technique_name
            )
            VALUES (?, ?, ?)
            """,
            (
                finding_id,
                technique_id,
                technique_name
            )
        )
        if commit:
            self.connection.commit()

        return cursor.lastrowid

    def get_case_mitre(self, case_id: str):
        cursor = self.connection.execute(
            """
            SELECT
                fm.finding_id,
                fm.technique_id,
                fm.technique_name
            FROM finding_mitre fm
            JOIN findings f
                ON f.finding_id = fm.finding_id
            WHERE f.case_id = ?
            ORDER BY fm.id
            """,
            (case_id,)
        )
        return cursor.fetchall()

    def get_finding_graph_data(self, finding_id: int):
        if self.connection is None:
            raise RuntimeError("Database is not connected")

        nodes = []
        edges = []

        finding = self.connection.execute(
            """
            SELECT
                finding_id,
                rule_id,
                title,
                severity,
                user,
                computer,
                evidence_id
            FROM findings
            WHERE finding_id = ?
            """,
            (finding_id,),
        ).fetchone()

        if finding is None:
            return {
                "nodes": [],
                "edges": [],
            }

        (
            finding_id,
            rule_id,
            title,
            severity,
            user,
            computer,
            evidence_id,
        ) = finding

        finding_key = f"finding:{finding_id}"

        nodes.append({
            "id": str(finding_id),
            "type": "finding",
            "attributes": {
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
            },
        })

        # Finding -> Events
        events = self.connection.execute(
            """
            SELECT
                e.id,
                e.event_id,
                e.record_id,
                e.timestamp,
                e.user,
                e.computer,
                e.evidence_id
            FROM events e
            JOIN finding_events fe
                ON fe.event_id = e.id
            WHERE fe.finding_id = ?
            ORDER BY e.id
            """,
            (finding_id,),
        ).fetchall()

        for event in events:
            (
                event_db_id,
                windows_event_id,
                record_id,
                timestamp,
                event_user,
                event_computer,
                event_evidence_id,
            ) = event

            event_key = f"event:{event_db_id}"

            nodes.append({
                "id": str(event_db_id),
                "type": "event",
                "attributes": {
                    "windows_event_id": windows_event_id,
                    "record_id": record_id,
                    "timestamp": timestamp,
                    "evidence_id": event_evidence_id,
                },
            })

            edges.append({
                "source": finding_key,
                "relation": "detected_from",
                "target": event_key,
            })

            # Event -> User
            if event_user:
                user_key = f"user:{event_user}"

                nodes.append({
                    "id": event_user,
                    "type": "user",
                    "attributes": {},
                })

                edges.append({
                    "source": user_key,
                    "relation": "generated",
                    "target": event_key,
                })

            # Event -> Computer
            if event_computer:
                computer_key = f"computer:{event_computer}"

                nodes.append({
                    "id": event_computer,
                    "type": "computer",
                    "attributes": {},
                })

                edges.append({
                    "source": computer_key,
                    "relation": "recorded",
                    "target": event_key,
                })

            # Event -> IOC
            iocs = self.connection.execute(
                """
                SELECT
                    i.ioc_id,
                    i.type,
                    i.value
                FROM iocs i
                JOIN ioc_events ie
                    ON ie.ioc_id = i.ioc_id
                WHERE ie.event_id = ?
                ORDER BY i.ioc_id
                """,
                (event_db_id,),
            ).fetchall()

            for ioc_id, ioc_type, ioc_value in iocs:
                ioc_key = f"{ioc_type}:{ioc_id}"

                nodes.append({
                    "id": str(ioc_id),
                    "type": ioc_type,
                    "attributes": {
                        "value": ioc_value,
                    },
                })

                edges.append({
                    "source": event_key,
                    "relation": "contains",
                    "target": ioc_key,
                })

            # Event -> Entity
            entities = self.connection.execute(
                """
                SELECT
                    en.entity_id,
                    en.type,
                    en.value
                FROM entities en
                JOIN entity_events ee
                    ON ee.entity_id = en.entity_id
                WHERE ee.event_id = ?
                ORDER BY en.entity_id
                """,
                (event_db_id,),
            ).fetchall()

            for entity_id, entity_type, entity_value in entities:
                entity_key = f"entity:{entity_id}"

                nodes.append({
                    "id": str(entity_id),
                    "type": "entity",
                    "attributes": {
                        "entity_type": entity_type,
                        "value": entity_value,
                    },
                })

                edges.append({
                    "source": entity_key,
                    "relation": "related_to",
                    "target": event_key,
                })

        # Finding -> MITRE
        mitre_rows = self.connection.execute(
            """
            SELECT technique_id, technique_name
            FROM finding_mitre
            WHERE finding_id = ?
            ORDER BY id
            """,
            (finding_id,),
        ).fetchall()

        for technique_id, technique_name in mitre_rows:
            mitre_key = f"mitre:{technique_id}"

            nodes.append({
                "id": technique_id,
                "type": "mitre",
                "attributes": {
                    "name": technique_name,
                },
            })

            edges.append({
                "source": finding_key,
                "relation": "mapped_to",
                "target": mitre_key,
            })

        # Remove duplicate nodes.
        unique_nodes = {}

        for node in nodes:
            key = f"{node['type']}:{node['id']}"
            unique_nodes[key] = node

        return {
            "nodes": list(unique_nodes.values()),
            "edges": edges,
        }