from pathlib import Path
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from analysis.engine import CaseAnalysisEngine
from cases.manager import CaseManager
from config import DATABASE_PATH
from evidence.acquisition import EvidenceAcquisition
from rules.security import (
    FailedLogonRule,
    ProcessCreationRule,
    SpecialPrivilegesRule,
    SuccessfulLogonRule,
)
from services.lifecycle import ForensicLifecycle
from storage.database import Database


class ForensicWorker(QObject):
    """Run one long-running forensic operation outside the Qt GUI thread."""

    status = pyqtSignal(str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, operation: str, **parameters: Any):
        super().__init__()
        self.operation = operation
        self.parameters = parameters

    @pyqtSlot()
    def run(self):
        result = None
        try:
            if self.operation == "acquire":
                result = self._acquire()
            elif self.operation == "parse_analyze":
                result = self._parse_analyze()
            elif self.operation == "report":
                result = self._report()
            else:
                raise ValueError(f"Unsupported forensic operation: {self.operation}")
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit(result)

    def _open_services(self):
        database_path = Path(self.parameters.get("database_path", DATABASE_PATH))
        case_manager = CaseManager(database_path)
        case_manager.connect()
        case_manager.create_tables()

        database = Database(database_path)
        database.connect()
        database.create_tables()
        return database, case_manager

    def _acquire(self):
        self.status.emit("Acquiring evidence and verifying SHA-256...")
        database, case_manager = self._open_services()
        try:
            lifecycle = ForensicLifecycle(
                database,
                case_manager,
                acquisition=EvidenceAcquisition(),
            )
            evidence_id, metadata = lifecycle.acquire_evidence(
                self.parameters["case_id"],
                Path(self.parameters["source"]),
                Path(self.parameters["destination"]),
            )
            return {"evidence_id": evidence_id, "metadata": metadata}
        finally:
            database.close()
            case_manager.close()

    def _parse_analyze(self):
        self.status.emit("Parsing EVTX evidence...")
        database, case_manager = self._open_services()
        try:
            lifecycle = ForensicLifecycle(database, case_manager)
            events = lifecycle.parse_evidence(
                self.parameters["case_id"],
                self.parameters["evidence_id"],
                Path(self.parameters["evidence_path"]),
            )
            self.status.emit(f"Analyzing {len(events):,} events...")
            result, persisted = lifecycle.analyze(
                self.parameters["case_id"],
                events,
                CaseAnalysisEngine([
                    FailedLogonRule(),
                    SuccessfulLogonRule(),
                    ProcessCreationRule(),
                    SpecialPrivilegesRule(),
                ]),
            )
            self.status.emit("Analysis complete")
            return {"events": len(events), "result": result, "persisted": persisted}
        finally:
            database.close()
            case_manager.close()

    def _report(self):
        self.status.emit("Generating forensic report...")
        database, case_manager = self._open_services()
        try:
            lifecycle = ForensicLifecycle(database, case_manager)
            return lifecycle.generate_report(
                self.parameters["case_id"],
                Path(self.parameters["output_path"]),
            )
        finally:
            database.close()
            case_manager.close()
