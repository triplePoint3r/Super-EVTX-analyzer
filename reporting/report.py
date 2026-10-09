from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class ForensicReportGenerator:
    """Generate a factual PDF report from persisted case data."""

    def __init__(self, database):
        self.database = database

    def generate(self, case_id: str, output_path: Path) -> Path:
        if self.database.connection is None:
            raise RuntimeError("Database is not connected")

        case = self.database.connection.execute(
            "SELECT case_id, name, description, status, created_at "
            "FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case is None:
            raise ValueError(f"Case not found: {case_id}")

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        styles = getSampleStyleSheet()
        document = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.55 * inch,
            leftMargin=0.55 * inch,
            topMargin=0.55 * inch,
            bottomMargin=0.55 * inch,
        )
        story = [
            Paragraph("Digital Forensics Investigation Report", styles["Title"]),
            Paragraph(f"Case: {case[1]}", styles["Heading2"]),
            self._table(
                [
                    ["Case ID", case[0]],
                    ["Description", case[2] or ""],
                    ["Status", case[3]],
                    ["Created", case[4]],
                ]
            ),
            Spacer(1, 12),
        ]

        sections = [
            ("Evidence", "SELECT filename, sha256, size, integrity_verified "
             "FROM evidence WHERE case_id = ?"),
            ("Findings", "SELECT rule_id, title, severity, timestamp, "
             "primary_event_id FROM findings WHERE case_id = ?"),
            ("IOCs", "SELECT type, value FROM iocs WHERE case_id = ?"),
            ("MITRE ATT&CK", "SELECT fm.technique_id, fm.technique_name "
             "FROM finding_mitre fm JOIN findings f ON f.finding_id = fm.finding_id "
             "WHERE f.case_id = ?"),
            ("Correlations", "SELECT type, user, description FROM correlations "
             "WHERE case_id = ?"),
            ("Anomalies", "SELECT type, count, description FROM anomalies "
             "WHERE case_id = ?"),
            ("Entities", "SELECT type, value FROM entities WHERE case_id = ?"),
            ("Chain of Custody", "SELECT action, timestamp, integrity_status, "
             "description FROM chain_of_custody WHERE case_id = ? "
             "ORDER BY custody_id"),
        ]
        for title, query in sections:
            rows = self.database.connection.execute(query, (case_id,)).fetchall()
            story.extend([Paragraph(title, styles["Heading2"])])
            if rows:
                story.append(self._table([[str(value) if value is not None else "" for value in row] for row in rows]))
            else:
                story.append(Paragraph("No persisted records.", styles["BodyText"]))
            story.append(Spacer(1, 10))

        event_statistics = self.database.connection.execute(
            """
            SELECT channel, event_id, COUNT(*)
            FROM events
            WHERE case_id = ?
            GROUP BY channel, event_id
            ORDER BY COUNT(*) DESC, event_id
            """,
            (case_id,),
        ).fetchall()
        story.extend([
            Paragraph("Event Statistics", styles["Heading2"]),
            self._table([
                [str(channel or ""), str(event_id or ""), str(count)]
                for channel, event_id, count in event_statistics
            ]) if event_statistics else Paragraph("No persisted events.", styles["BodyText"]),
            Spacer(1, 10),
        ])

        graph_counts = []
        for label, table in (
            ("Events", "events"),
            ("Findings", "findings"),
            ("IOCs", "iocs"),
            ("Entities", "entities"),
            ("Correlations", "correlations"),
            ("Anomalies", "anomalies"),
        ):
            count = self.database.connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE case_id = ?",
                (case_id,),
            ).fetchone()[0]
            graph_counts.append([label, str(count)])
        story.extend([
            Paragraph("Investigation Graph Summary", styles["Heading2"]),
            self._table(graph_counts),
            Spacer(1, 10),
        ])

        risk = self.database.connection.execute(
            "SELECT risk_score, risk_level FROM case_risk WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        story.extend([
            Paragraph("Risk Assessment", styles["Heading2"]),
            Paragraph(
                f"Score: {risk[0]}, Level: {risk[1]}" if risk else "No risk assessment persisted.",
                styles["BodyText"],
            ),
        ])
        document.build(story)
        return output_path

    @staticmethod
    def _table(rows):
        table = Table(rows, repeatRows=1 if len(rows) > 1 else 0)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        return table
