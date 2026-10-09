import getpass
import os
from pathlib import Path

from cases.manager import CaseManager
from evidence.acquisition import EvidenceAcquisition
from parsers.evtx_parser import EvtxParser
from reporting.report import ForensicReportGenerator


class ForensicLifecycle:
    """Coordinate forensic operations and record their custody events centrally."""

    def __init__(
        self,
        database,
        case_manager: CaseManager | None = None,
        acquisition: EvidenceAcquisition | None = None,
        parser: EvtxParser | None = None,
        actor: str | None = None,
    ):
        self.database = database
        self.case_manager = case_manager
        self.acquisition = acquisition or EvidenceAcquisition()
        self.parser = parser or EvtxParser()
        self.actor = actor or getpass.getuser()
        self.process_id = str(os.getpid())

    def acquire_evidence(self, case_id: str, source: Path, destination: Path):
        metadata = self.acquisition.acquire(source, destination)
        if self.case_manager is None:
            raise RuntimeError("CaseManager is required to register evidence")
        evidence_id = self.case_manager.add_evidence(case_id, metadata)
        self.database.insert_chain_of_custody(
            case_id=case_id,
            evidence_id=evidence_id,
            action="EVIDENCE_ACQUIRED",
            actor=self.actor,
            process_id=self.process_id,
            description=f"Acquired {metadata.filename}",
            sha256=metadata.sha256,
            integrity_status="VALID",
        )
        self.database.insert_chain_of_custody(
            case_id=case_id,
            evidence_id=evidence_id,
            action="HASH_VERIFIED",
            actor=self.actor,
            process_id=self.process_id,
            description="Source and acquired evidence hashes match",
            sha256=metadata.sha256,
            integrity_status="VALID",
        )
        return evidence_id, metadata

    def parse_evidence(self, case_id: str, evidence_id: str, path: Path):
        events = list(self.parser.parse(path, evidence_id=evidence_id))
        for event in events:
            event.case_id = case_id
        self.database.insert_events(events, case_id=case_id)
        self.database.insert_chain_of_custody(
            case_id=case_id,
            evidence_id=evidence_id,
            action="EVIDENCE_PARSED",
            actor=self.actor,
            process_id=self.process_id,
            description=f"Parsed {len(events)} normalized events",
            integrity_status="VALID",
        )
        return events

    def analyze(self, case_id: str, events, analysis_engine):
        result = analysis_engine.analyze(events, case_id=case_id)
        persisted = self.database.persist_analysis_result(result, events, case_id)
        evidence_ids = sorted({event.evidence_id for event in events if event.evidence_id})
        for evidence_id in evidence_ids:
            self.database.insert_chain_of_custody(
                case_id=case_id,
                evidence_id=evidence_id,
                action="ANALYSIS_PERFORMED",
                actor=self.actor,
                process_id=self.process_id,
                description="Detection, correlation, intelligence, and anomaly analysis completed",
                integrity_status="VALID",
            )
        return result, persisted

    def generate_report(self, case_id: str, output_path: Path):
        report_path = ForensicReportGenerator(self.database).generate(case_id, output_path)
        evidence_rows = self.case_manager.get_case_evidence(case_id) if self.case_manager else []
        for evidence_row in evidence_rows:
            self.database.insert_chain_of_custody(
                case_id=case_id,
                evidence_id=evidence_row[0],
                action="REPORT_GENERATED",
                actor=self.actor,
                process_id=self.process_id,
                description=f"Generated report {report_path.name}",
                integrity_status="VALID",
            )
        return report_path

    def is_evidence_processed(
        self,
        case_id: str,
        evidence_id: str,
    ) -> bool:
        return self.database.evidence_has_custody_action(
        case_id,
        evidence_id,
        "EVIDENCE_PARSED",
        )
