from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class EventSearchFilters:
    case_id: str | None = None
    evidence_id: str | None = None
    start_time: datetime | str | None = None
    end_time: datetime | str | None = None
    event_id: int | None = None
    channel: str | None = None
    provider: str | None = None
    computer: str | None = None
    user: str | None = None
    level: str | None = None
    keyword: str | None = None
    ioc: str | None = None
    finding: str | None = None
    severity: str | None = None
    mitre_technique: str | None = None


class EventSearch:
    """Reusable parameterized search over persisted events and lineage."""

    def __init__(self, database):
        self.database = database

    def search(self, filters: EventSearchFilters | None = None) -> list[dict[str, Any]]:
        if self.database.connection is None:
            raise RuntimeError("Database is not connected")

        filters = filters or EventSearchFilters()
        clauses = []
        parameters: list[Any] = []

        def add(condition: str, *values: Any):
            clauses.append(condition)
            parameters.extend(values)

        if filters.case_id is not None:
            add("e.case_id = ?", filters.case_id)
        if filters.evidence_id is not None:
            add("e.evidence_id = ?", filters.evidence_id)
        if filters.start_time is not None:
            add("e.timestamp >= ?", self._timestamp(filters.start_time))
        if filters.end_time is not None:
            add("e.timestamp <= ?", self._timestamp(filters.end_time))
        if filters.event_id is not None:
            add("e.event_id = ?", filters.event_id)
        for name in ("channel", "provider", "computer", "user", "level"):
            value = getattr(filters, name)
            if value is not None:
                add(f"e.{name} LIKE ?", f"%{value}%")
        if filters.keyword:
            keyword = f"%{filters.keyword}%"
            add(
                "(e.event_data LIKE ? OR e.raw_xml LIKE ? OR e.user LIKE ? "
                "OR e.computer LIKE ? OR e.provider LIKE ?)",
                keyword,
                keyword,
                keyword,
                keyword,
                keyword,
            )
        if filters.ioc:
            add("(i.value LIKE ? OR i.type LIKE ?)", f"%{filters.ioc}%", f"%{filters.ioc}%")
        if filters.finding:
            value = f"%{filters.finding}%"
            add("(f.rule_id LIKE ? OR f.title LIKE ? OR f.description LIKE ?)", value, value, value)
        if filters.severity:
            add("f.severity = ?", filters.severity)
        if filters.mitre_technique:
            add("fm.technique_id = ?", filters.mitre_technique)

        query = """
            SELECT DISTINCT
                e.id,
                e.case_id,
                e.evidence_id,
                e.event_id,
                e.record_id,
                e.timestamp,
                e.channel,
                e.computer,
                e.provider,
                e.level,
                e.user
            FROM events e
            LEFT JOIN finding_events fe ON fe.event_id = e.id
            LEFT JOIN findings f ON f.finding_id = fe.finding_id
            LEFT JOIN finding_mitre fm ON fm.finding_id = f.finding_id
            LEFT JOIN ioc_events ie ON ie.event_id = e.id
            LEFT JOIN iocs i ON i.ioc_id = ie.ioc_id
        """
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY e.timestamp, e.id"

        cursor = self.database.connection.execute(query, parameters)
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    @staticmethod
    def _timestamp(value: datetime | str) -> str:
        return value.isoformat() if isinstance(value, datetime) else value
