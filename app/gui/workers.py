from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from analysis.engine import CaseAnalysisEngine
from cases.manager import CaseManager
from config import DATABASE_PATH
from rules.security import (
    FailedLogonRule,
    ProcessCreationRule,
    SpecialPrivilegesRule,
    SuccessfulLogonRule,
)
from services.lifecycle import ForensicLifecycle
from storage.database import Database


class ParseAnalyzeWorker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(
        self,
        case_id: str,
        evidence_id: str,
        evidence_path: Path,
    ):
        super().__init__()
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.evidence_path = evidence_path

    @pyqtSlot()
    def run(self):
        database = None
        case_manager = None

        try:
            self.status.emit("Opening forensic database...")

            # IMPORTANT:
            # These connections belong to the worker thread.
            case_manager = CaseManager(DATABASE_PATH)
            case_manager.connect()
            case_manager.create_tables()

            database = Database(DATABASE_PATH)
            database.connect()
            database.create_tables()

            lifecycle = ForensicLifecycle(
                database,
                case_manager,
            )

            self.status.emit(
                f"Parsing evidence: {self.evidence_path.name}"
            )

            if lifecycle.is_evidence_processed(self.case_id,self.evidence_id,):
                 self.status.emit("Evidence has already been parsed. ""Skipping duplicate parsing.")
                 self.finished.emit({"already_processed": True,"events": database.count_events_for_evidence(self.case_id,self.evidence_id,),}) 
                 return

            events = lifecycle.parse_evidence(
                self.case_id,
                self.evidence_id,
                self.evidence_path,
            )

            self.status.emit(
                f"Parsed {len(events):,} events. Starting analysis..."
            )

            analysis_engine = CaseAnalysisEngine([
                FailedLogonRule(),
                SuccessfulLogonRule(),
                ProcessCreationRule(),
                SpecialPrivilegesRule(),
            ])

            result, persisted = lifecycle.analyze(
                self.case_id,
                events,
                analysis_engine,
            )

            self.status.emit(
                f"Analysis completed: {len(result.get('findings', [])):,} findings"
            )

            self.finished.emit({
                "events": len(events),
                "result": result,
                "persisted": persisted,
            })

        except Exception as exc:
            self.error.emit(
                f"{type(exc).__name__}: {exc}"
            )
            self.finished.emit(None)

        finally:
            if database is not None:
                database.close()

            if case_manager is not None:
                case_manager.close()