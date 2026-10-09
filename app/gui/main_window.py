import uuid
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QDateTime, Qt, QThread
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QInputDialog,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from app.gui.workers import ParseAnalyzeWorker
from investigation.graph_view import InvestigationGraphView
from evidence.acquisition import EvidenceAcquisition
from reporting.report import ForensicReportGenerator
from services.lifecycle import ForensicLifecycle


class SortableItem(QTableWidgetItem):
    """QTableWidgetItem with numeric/date-aware sorting."""
    def __lt__(self, other):
        left = self.text()
        right = other.text()

        # Severity sorting
        severity_order = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3,
        }

        if left.casefold() in severity_order and right.casefold() in severity_order:
            return severity_order[left.casefold()] < severity_order[right.casefold()]

        # Numeric / date sorting
        for parser in (
            lambda value: float(value.replace(",", "")),
            lambda value: datetime.fromisoformat(
            value.replace("Z", "+00:00")
            ).timestamp(),
        ):
            try:
                return parser(left) < parser(right)
            except (ValueError, TypeError, OverflowError):
                pass

        # Normal alphabetical sorting
        return left.casefold() < right.casefold()


class DetailsDialog(QDialog):
    """Simple read-only details dialog for a selected table row."""

    def __init__(self, parent, headers, values, title="Details"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(700, 500)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        for header, value in zip(headers, values):
            label = QLabel(str(value))
            label.setWordWrap(True)
            form.addRow(f"{header}:", label)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class FilterableTable(QWidget):
    """Reusable, user-friendly table with search, filtering, sorting and copy."""

    def __init__(self, title, headers, rows, parent=None, specialized_filter=None):
        super().__init__(parent)
        self.title = title
        self.headers = headers
        self.all_rows = [tuple(row) for row in rows]
        self.specialized_filter = specialized_filter

        layout = QVBoxLayout(self)

        controls = QGroupBox("Search & Filter")
        controls_layout = QVBoxLayout(controls)

        row1 = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search all columns..." if not headers else "Search..."
        )
        self.search.setClearButtonEnabled(True)

        self.column = QComboBox()
        self.column.addItem("All columns")
        self.column.addItems(headers)

        self.filter_value = QLineEdit()
        self.filter_value.setPlaceholderText("Optional column filter...")
        self.filter_value.setClearButtonEnabled(True)

        row1.addWidget(QLabel("Search:"))
        row1.addWidget(self.search, 2)
        row1.addWidget(QLabel("Column:"))
        row1.addWidget(self.column)
        row1.addWidget(self.filter_value, 2)

        row2 = QHBoxLayout()
        self.apply_btn = QPushButton("🔍 Apply")
        self.clear_btn = QPushButton("🗑️ Clear")
        self.copy_btn = QPushButton("📋 Copy Selected")
        self.details_btn = QPushButton("🔎 View Details")
        self.refresh_btn = QPushButton("🔄 Refresh")

        self.count_label = QLabel()
        row2.addWidget(self.apply_btn)
        row2.addWidget(self.clear_btn)
        row2.addWidget(self.copy_btn)
        row2.addWidget(self.details_btn)
        row2.addWidget(self.refresh_btn)
        row2.addStretch()
        row2.addWidget(self.count_label)

        controls_layout.addLayout(row1)
        controls_layout.addLayout(row2)
        layout.addWidget(controls)

        self.table = QTableWidget()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setWordWrap(False)
        self.table.setShowGrid(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setUpdatesEnabled(False)
        self.table.setToolTip(
            "Click a column header to sort. Select rows to copy or inspect."
        )
        layout.addWidget(self.table)

        self.search.returnPressed.connect(self.apply_filter)
        self.filter_value.returnPressed.connect(self.apply_filter)
        self.apply_btn.clicked.connect(self.apply_filter)
        self.clear_btn.clicked.connect(self.clear_filter)
        self.copy_btn.clicked.connect(self.copy_selected)
        self.details_btn.clicked.connect(self.show_details)
        self.table.cellDoubleClicked.connect(
            lambda row, _column: self.show_details(row)
        )
        self.refresh_btn.clicked.connect(self.refresh_data)

        self._render(self.all_rows)

    def set_rows(self, rows):
        self.all_rows = [tuple(row) for row in rows]
        self.apply_filter()

    def refresh_data(self):
        if self.parent() is not None:
            window = self.window()
            if hasattr(window, "refresh"):
                window.refresh()
        else:
            self.apply_filter()

    def _matches(self, row):
        search = self.search.text().strip().casefold()
        if search:
            if search not in " ".join(str(value) for value in row).casefold():
                return False

        filter_text = self.filter_value.text().strip().casefold()
        if filter_text:
            if self.column.currentIndex() == 0:
                haystack = " ".join(str(value) for value in row)
            else:
                index = self.column.currentIndex() - 1
                haystack = str(row[index]) if index < len(row) else ""
            if filter_text not in haystack.casefold():
                return False

        if self.specialized_filter and not self.specialized_filter(row):
            return False

        return True

    def apply_filter(self):
        filtered = [row for row in self.all_rows if self._matches(row)]
        self._render(filtered)

    def clear_filter(self):
        self.search.clear()
        self.column.setCurrentIndex(0)
        self.filter_value.clear()
        if self.specialized_filter and hasattr(self, "clear_specialized"):
            self.clear_specialized()
        self._render(self.all_rows)

    def _render(self, rows):
        self.table.setSortingEnabled(False)
        self.table.clearContents()
        self.table.setColumnCount(len(self.headers))
        self.table.setHorizontalHeaderLabels(self.headers)
        self.table.setRowCount(len(rows))

        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                self.table.setItem(r, c, SortableItem(str(value)))

        self.table.setSortingEnabled(True)
        self.table.setUpdatesEnabled(True)
        self.table.setColumnWidth(0, 100)
        self.count_label.setText(f"Showing {len(rows):,} of {len(self.all_rows):,}")

    def copy_selected(self):
        selected_rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        if not selected_rows:
            QMessageBox.information(self, "Copy", "Select one or more rows first.")
            return

        lines = ["\t".join(self.headers)]
        for row in selected_rows:
            values = [
                self.table.item(row, column).text()
                if self.table.item(row, column)
                else ""
                for column in range(self.table.columnCount())
            ]
            lines.append("\t".join(values))

        QApplication.clipboard().setText("\n".join(lines))
        self.window().statusBar().showMessage(
            f"Copied {len(selected_rows):,} row(s) to clipboard."
        )

    def show_details(self, row=None):
        if row is None:
            selected = self.table.selectionModel().selectedRows()
            if not selected:
                QMessageBox.information(self, "Details", "Select a row first.")
                return
            row = selected[0].row()

        values = [
            self.table.item(row, column).text()
            if self.table.item(row, column)
            else ""
            for column in range(self.table.columnCount())
        ]
        DetailsDialog(self, self.headers, values, f"{self.title} Details").exec()


class TimelineTable(FilterableTable):
    """Timeline table with the Phase-4 channel, Event ID and time filters."""

    CHANNEL_INDEX = 5
    EVENT_ID_INDEX = 2
    TIMESTAMP_INDEX = 4

    def __init__(self, rows, parent=None):
        self.channels = []
        self.event_ids = set()
        self.start_dt = None
        self.end_dt = None

        super().__init__(
            "Timeline",
            MainWindow._headers_for("Timeline"),
            rows,
            parent=parent,
            specialized_filter=self._timeline_matches,
        )

        group = QGroupBox("Timeline Filters")
        group_layout = QVBoxLayout(group)

        channel_row = QHBoxLayout()
        channel_row.addWidget(QLabel("Channels:"))
        self.channel_checks = {}
        for channel in (
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
        ):
            check = QCheckBox(channel)
            check.toggled.connect(self.apply_filter)
            self.channel_checks[channel.casefold()] = check
            channel_row.addWidget(check)
        channel_row.addStretch()
        group_layout.addLayout(channel_row)

        event_row = QHBoxLayout()
        event_row.addWidget(QLabel("Event ID(s):"))
        self.event_ids_input = QLineEdit()
        self.event_ids_input.setPlaceholderText("e.g. 4624, 4625, 4688")
        self.event_ids_input.returnPressed.connect(self.apply_filter)
        event_row.addWidget(self.event_ids_input, 2)
        group_layout.addLayout(event_row)

        time_row = QHBoxLayout()

        self.start_enabled = QCheckBox("Start")
        self.start_dt_edit = QDateTimeEdit(QDateTime.currentDateTime())
        self.start_dt_edit.setCalendarPopup(True)
        self.start_dt_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.start_dt_edit.setEnabled(False)
        self.start_enabled.toggled.connect(self.start_dt_edit.setEnabled)
        self.start_enabled.toggled.connect(self.apply_filter)
        self.start_dt_edit.dateTimeChanged.connect(self.apply_filter)

        self.end_enabled = QCheckBox("End")
        self.end_dt_edit = QDateTimeEdit(QDateTime.currentDateTime())
        self.end_dt_edit.setCalendarPopup(True)
        self.end_dt_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.end_dt_edit.setEnabled(False)
        self.end_enabled.toggled.connect(self.end_dt_edit.setEnabled)
        self.end_enabled.toggled.connect(self.apply_filter)
        self.end_dt_edit.dateTimeChanged.connect(self.apply_filter)

        time_row.addWidget(self.start_enabled)
        time_row.addWidget(self.start_dt_edit)
        time_row.addSpacing(12)
        time_row.addWidget(self.end_enabled)
        time_row.addWidget(self.end_dt_edit)
        time_row.addStretch()

        group_layout.addLayout(time_row)

        # Insert specialized filters directly above the table.
        self.layout().insertWidget(1, group)

        self.clear_specialized = self._clear_timeline_filters

    def _timeline_matches(self, row):
        selected_channels = {
            key for key, check in self.channel_checks.items() if check.isChecked()
        }
        if selected_channels:
            channel = str(row[self.CHANNEL_INDEX]).casefold()
            if not any(value in channel for value in selected_channels):
                return False

        event_ids = {
            value.strip()
            for value in self.event_ids_input.text().split(",")
            if value.strip()
        }
        if event_ids and str(row[self.EVENT_ID_INDEX]).strip() not in event_ids:
            return False

        timestamp = str(row[self.TIMESTAMP_INDEX]).strip()
        try:
            event_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            event_dt = None

        if event_dt is not None:
            if self.start_enabled.isChecked():
                start = self.start_dt_edit.dateTime().toPyDateTime()
                if event_dt.tzinfo is not None and start.tzinfo is None:
                    start = start.replace(tzinfo=event_dt.tzinfo)
                if event_dt < start:
                    return False

            if self.end_enabled.isChecked():
                end = self.end_dt_edit.dateTime().toPyDateTime()
                if event_dt.tzinfo is not None and end.tzinfo is None:
                    end = end.replace(tzinfo=event_dt.tzinfo)
                if event_dt > end:
                    return False

        return True

    def _clear_timeline_filters(self):
        for check in self.channel_checks.values():
            check.setChecked(False)
        self.event_ids_input.clear()
        self.start_enabled.setChecked(False)
        self.end_enabled.setChecked(False)


class PagedTimelineTable(QWidget):
    """Database-backed timeline: only a small page is materialized in Qt."""

    PAGE_SIZE = 200
    HEADERS = [
        "DB ID", "Evidence ID", "Event ID", "Record ID", "Timestamp",
        "Channel", "Computer", "Provider", "Level", "User",
    ]
    SORT_COLUMNS = {
        0: "id", 1: "evidence_id", 2: "event_id", 3: "record_id",
        4: "timestamp", 5: "channel", 6: "computer", 7: "provider",
        8: "level", 9: "user",
    }

    def __init__(self, database, case_id, parent=None):
        super().__init__(parent)
        self.database = database
        self.case_id = case_id
        self.page = 0
        self.sort_column = "timestamp"
        self.sort_desc = False
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search timeline (channel, computer, provider, user)...")
        self.event_ids = QLineEdit()
        self.event_ids.setPlaceholderText("Event IDs: 4624,4625")
        self.channel = QLineEdit()
        self.channel.setPlaceholderText("Channel contains...")
        self.apply_btn = QPushButton("Apply filters")
        self.clear_btn = QPushButton("Clear")
        controls.addWidget(self.search, 3)
        controls.addWidget(self.event_ids, 1)
        controls.addWidget(self.channel, 2)
        controls.addWidget(self.apply_btn)
        controls.addWidget(self.clear_btn)
        layout.addLayout(controls)

        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setSortingEnabled(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        footer = QHBoxLayout()
        self.prev_btn = QPushButton("← Previous")
        self.next_btn = QPushButton("Next →")
        self.copy_btn = QPushButton("Copy selected")
        self.count_label = QLabel()
        footer.addWidget(self.prev_btn)
        footer.addWidget(self.next_btn)
        footer.addWidget(self.copy_btn)
        footer.addStretch()
        footer.addWidget(self.count_label)
        layout.addLayout(footer)

        self.apply_btn.clicked.connect(self.apply_filters)
        self.clear_btn.clicked.connect(self.clear_filters)
        self.search.returnPressed.connect(self.apply_filters)
        self.event_ids.returnPressed.connect(self.apply_filters)
        self.channel.returnPressed.connect(self.apply_filters)
        self.prev_btn.clicked.connect(self.previous_page)
        self.next_btn.clicked.connect(self.next_page)
        self.copy_btn.clicked.connect(self.copy_selected)
        self.table.horizontalHeader().sectionClicked.connect(self.sort_by_column)
        self.load_page()

    def _where(self):
        clauses = ["case_id = ?"]
        params = [self.case_id]
        search = self.search.text().strip()
        if search:
            pattern = f"%{search}%"
            clauses.append("(channel LIKE ? OR computer LIKE ? OR provider LIKE ? OR user LIKE ?)")
            params.extend([pattern] * 4)
        channel = self.channel.text().strip()
        if channel:
            clauses.append("channel LIKE ?")
            params.append(f"%{channel}%")
        ids = [part.strip() for part in self.event_ids.text().split(",") if part.strip()]
        if ids:
            valid_ids = []
            for item in ids:
                try:
                    valid_ids.append(int(item))
                except ValueError:
                    continue
            if not valid_ids:
                clauses.append("0")
            else:
                clauses.append("event_id IN (" + ",".join("?" for _ in valid_ids) + ")")
                params.extend(valid_ids)
        return " AND ".join(clauses), params

    def apply_filters(self):
        self.page = 0
        self.load_page()

    def clear_filters(self):
        self.search.clear()
        self.event_ids.clear()
        self.channel.clear()
        self.page = 0
        self.load_page()

    def previous_page(self):
        if self.page > 0:
            self.page -= 1
            self.load_page()

    def next_page(self):
        if (self.page + 1) * self.PAGE_SIZE < self.total_rows:
            self.page += 1
            self.load_page()

    def sort_by_column(self, column):
        column_name = self.SORT_COLUMNS.get(column)
        if not column_name:
            return
        if self.sort_column == column_name:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_column = column_name
            self.sort_desc = False
        self.page = 0
        self.load_page()

    def load_page(self):
        where, params = self._where()
        conn = self.database.connection
        self.total_rows = conn.execute(
            f"SELECT COUNT(*) FROM events WHERE {where}", params
        ).fetchone()[0]
        direction = "DESC" if self.sort_desc else "ASC"
        offset = self.page * self.PAGE_SIZE
        rows = conn.execute(
            f"SELECT id, evidence_id, event_id, record_id, timestamp, channel, computer, provider, level, user "
            f"FROM events WHERE {where} ORDER BY {self.sort_column} {direction}, id LIMIT ? OFFSET ?",
            [*params, self.PAGE_SIZE, offset],
        ).fetchall()
        self.table.setUpdatesEnabled(False)
        self.table.setSortingEnabled(False)
        self.table.clearContents()
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                self.table.setItem(r, c, QTableWidgetItem("" if value is None else str(value)))
        self.table.setUpdatesEnabled(True)
        self.prev_btn.setEnabled(self.page > 0)
        self.next_btn.setEnabled((self.page + 1) * self.PAGE_SIZE < self.total_rows)
        start = offset + 1 if self.total_rows else 0
        end = min(offset + len(rows), self.total_rows)
        self.count_label.setText(f"Rows {start:,}–{end:,} of {self.total_rows:,}  |  Page size {self.PAGE_SIZE}")

    def copy_selected(self):
        selected = sorted({idx.row() for idx in self.table.selectionModel().selectedRows()})
        if not selected:
            QMessageBox.information(self, "Copy", "Select one or more rows first.")
            return
        lines = ["\t".join(self.HEADERS)]
        for row in selected:
            lines.append("\t".join(
                self.table.item(row, col).text() if self.table.item(row, col) else ""
                for col in range(self.table.columnCount())
            ))
        QApplication.clipboard().setText("\n".join(lines))


class MainWindow(QMainWindow):
    """Case-aware EVTX forensic dashboard with user-friendly investigation tables."""

    def __init__(self, database, case_manager=None, case_id: str | None = None):
        super().__init__()
        self.database = database
        self.case_manager = case_manager
        self.case_id = case_id
        self._thread = None
        self._worker = None
        self._busy = False
        # These attributes must exist before QTabWidget emits currentChanged.
        self.graph_view = None
        self.graph_placeholder = None
        self.graph_tab_index = -1

        self.setWindowTitle("EVTX Forensics Investigation")
        self.resize(1300, 800)
        self.statusBar().showMessage("Ready.")

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.setCentralWidget(self.tabs)

        self._build_toolbar()
        self.refresh()

    def _build_toolbar(self):
        toolbar = QToolBar("Investigation")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        actions = (
            ("New Case", "Create a new forensic case.", self.create_case),
            ("Open Case", "Open an existing case.", self.open_case),
            ("Add Evidence", "Add an EVTX file to the current case.", self.add_evidence),
            ("Parse and Analyze", "Parse and analyze the latest evidence.", self.parse_and_analyze),
            ("Generate Report", "Generate a PDF forensic report.", self.generate_report),
            ("Refresh", "Refresh the current case and all investigation views.", self.refresh),
        )

        for label, tooltip, handler in actions:
            action = QAction(label, self)
            action.setToolTip(tooltip)
            action.triggered.connect(handler)
            toolbar.addAction(action)

    def create_case(self):
        if self.case_manager is None:
            return
        name, accepted = QInputDialog.getText(self, "New Case", "Case name:")
        if accepted and name.strip():
            self.case_id = self.case_manager.create_case(name.strip())
            self.statusBar().showMessage(f"Case created: {name.strip()}")
            self.refresh()

    def open_case(self):
        if self.case_manager is None:
            return

        cases = self.case_manager.list_cases()
        if not cases:
            QMessageBox.information(self, "Cases", "No cases exist yet.")
            return

        labels = [f"{row[1]} ({row[0]})" for row in cases]
        selected, accepted = QInputDialog.getItem(
            self, "Open Case", "Case:", labels, 0, False
        )
        if accepted:
            self.case_id = cases[labels.index(selected)][0]
            self.statusBar().showMessage(f"Opened case: {selected}")
            self.refresh()

    def add_evidence(self):
        if self.case_id is None or self.case_manager is None:
            QMessageBox.information(self, "Evidence", "Create or open a case first.")
            return

        source_text, _ = QFileDialog.getOpenFileName(
            self,
            "Select EVTX Evidence",
            "",
            "Windows Event Log (*.evtx);;All Files (*.*)",
        )
        if not source_text:
            return

        source = Path(source_text)
        destination = Path.cwd() / "data" / "evidence" / (
            f"{source.stem}_{uuid.uuid4().hex}{source.suffix.lower()}"
        )

        try:
            lifecycle = ForensicLifecycle(
                self.database,
                self.case_manager,
                acquisition=EvidenceAcquisition(),
            )
            lifecycle.acquire_evidence(self.case_id, source, destination)
            self.statusBar().showMessage(f"Evidence added: {source.name}")
            self.refresh()
        except Exception as exc:
            QMessageBox.critical(self, "Evidence Acquisition Failed", str(exc))

    def parse_and_analyze(self):
        if self._busy:
            return

        if self.case_id is None or self.case_manager is None:
            QMessageBox.information(self, "Analysis", "Create or open a case first.")
            return

        evidence = self.case_manager.get_case_evidence(self.case_id)
        if not evidence:
            QMessageBox.information(self, "Analysis", "Add evidence first.")
            return

        evidence_id = evidence[-1][0]
        evidence_path = Path(evidence[-1][3])

        reply = QMessageBox.question(
            self,
            "Parse and Analyze",
            f"Process evidence:\n{evidence[-1][1]}\n\nThis may take some time.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._busy = True
        self.statusBar().showMessage("Parsing and analyzing evidence...")

        self._thread = QThread(self)
        self._worker = ParseAnalyzeWorker(
            case_id=self.case_id,
            evidence_id=evidence_id,
            evidence_path=evidence_path,
        )
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.status.connect(self.statusBar().showMessage)
        self._worker.error.connect(self._on_worker_error)
        self._worker.finished.connect(self._on_parse_finished)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._on_thread_finished)
        self._thread.start()

    def generate_report(self):
        if self.case_id is None:
            QMessageBox.information(self, "Report", "Create or open a case first.")
            return

        output, _ = QFileDialog.getSaveFileName(
            self,
            "Save Forensic Report",
            str(Path.cwd() / "data" / "reports" / f"{self.case_id}.pdf"),
            "PDF Report (*.pdf)",
        )
        if not output:
            return

        try:
            lifecycle = ForensicLifecycle(self.database, self.case_manager)
            lifecycle.generate_report(self.case_id, Path(output))
            QMessageBox.information(
                self, "Report Generated", f"Report saved to:\n{output}"
            )
            self.statusBar().showMessage("Report generated successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Report Failed", str(exc))

    @staticmethod
    def _headers_for(title):
        return {
            "Evidence": [
                "Evidence ID", "Filename", "Original Path", "Acquired Path",
                "Size", "SHA-256", "Created", "Modified", "Accessed", "Integrity"
            ],
            "Findings": [
                "Finding ID", "Rule ID", "Title", "Severity", "Timestamp",
                "Event ID", "Primary Event ID", "Evidence ID", "Case ID"
            ],
            "IOCs": ["IOC ID", "Event IDs", "Type", "Value"],
            "MITRE": ["Finding ID", "Technique ID", "Technique Name"],
            "Custody": [
                "Custody ID", "Evidence ID", "Event ID", "Action", "Timestamp",
                "Actor", "Process ID", "Description", "SHA-256",
                "Integrity", "Details"
            ],
            "Timeline": [
                "DB ID", "Evidence ID", "Event ID", "Record ID", "Timestamp",
                "Channel", "Computer", "Provider", "Level", "User"
            ],
        }[title]

    def _make_table(self, title, rows):
        if title == "Timeline":
            return PagedTimelineTable(self.database, self.case_id, parent=self)
        return FilterableTable(
            title,
            self._headers_for(title),
            rows,
            parent=self,
        )

    def refresh(self):
        # Invalidate graph-tab state before clearing tabs: clear()/addTab() can
        # emit currentChanged synchronously while the tab collection is rebuilt.
        self.graph_view = None
        self.graph_placeholder = None
        self.graph_tab_index = -1
        self.tabs.clear()

        if self.case_id is None:
            dashboard = QWidget()
            layout = QVBoxLayout(dashboard)
            label = QLabel(
                "No case selected.\n\n"
                "Create a new case or open an existing case to begin an investigation."
            )
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setWordWrap(True)
            layout.addWidget(label)
            self.tabs.addTab(dashboard, "Dashboard")
            self.statusBar().showMessage("Ready - create or open a case.")
            return

        summary = self.database.get_case_summary(self.case_id)
        case = summary["case"]

        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)

        title = QLabel(f"<h2>{case['name']}</h2><p>Case ID: {case['case_id']}</p>")
        title.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(title)

        form = QFormLayout()
        for label, value in (
            ("Status", case["status"]),
            ("Evidence", summary["evidence_count"]),
            ("Events", summary["event_count"]),
            ("Findings", summary["finding_count"]),
            ("IOCs", summary["ioc_count"]),
            ("Correlations", summary["correlation_count"]),
            ("Anomalies", summary["anomaly_count"]),
            ("Risk", f"{summary['risk_score']} ({summary['risk_level']})"),
        ):
            form.addRow(label, QLabel(str(value)))

        layout.addLayout(form)
        refresh_btn = QPushButton("🔄 Refresh Case")
        refresh_btn.clicked.connect(self.refresh)
        layout.addWidget(refresh_btn)
        layout.addStretch()

        self.tabs.addTab(dashboard, "Dashboard")

        self.tabs.addTab(
            self._make_table("Evidence", self.case_manager.get_case_evidence(self.case_id)),
            "Evidence",
        )
        self.tabs.addTab(
            self._make_table("Findings", self.database.get_case_findings(self.case_id)),
            "Findings",
        )
        self.tabs.addTab(
            self._make_table("IOCs", self.database.get_case_iocs(self.case_id)),
            "IOCs",
        )
        self.tabs.addTab(
            self._make_table("MITRE", self.database.get_case_mitre(self.case_id)),
            "MITRE",
        )
        self.tabs.addTab(
            self._make_table("Custody", self.database.get_case_custody(self.case_id)),
            "Custody",
        )
        # Timeline is paged directly from SQLite; never materialize every event in Qt.
        self.tabs.addTab(self._make_table("Timeline", []), "Timeline")

        # Constructing a graph can be expensive. Defer it until the user opens the tab.
        self.graph_view = None
        self.graph_placeholder = QWidget()
        graph_layout = QVBoxLayout(self.graph_placeholder)
        graph_label = QLabel("The investigation graph loads when this tab is opened.")
        graph_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        graph_layout.addWidget(graph_label)
        self.graph_tab_index = self.tabs.addTab(self.graph_placeholder, "Graph")

        self.statusBar().showMessage(
            f"Case loaded: {case['name']} | "
            f"{summary['event_count']:,} events | "
            f"{summary['finding_count']:,} findings"
        )

    def _on_tab_changed(self, index):
        if index != getattr(self, "graph_tab_index", -1) or self.case_id is None:
            return
        if getattr(self, "graph_view", None) is not None:
            return
        # Tab signals can fire while tabs are being cleared/rebuilt. Validate
        # the index and widget before replacing the lazy-load placeholder.
        if index < 0 or index >= self.tabs.count():
            return
        old = self.tabs.widget(index)
        if old is None or self.tabs.tabText(index) != "Graph":
            return

        graph = InvestigationGraphView(self.database, self.case_id, parent=self.tabs)
        self.tabs.removeTab(index)
        if old is not None:
            old.deleteLater()
        self.graph_view = graph
        self.graph_tab_index = self.tabs.insertTab(index, graph, "Graph")
        self.tabs.setCurrentIndex(index)

    def export_report(self, output_path: Path) -> Path:
        if self.case_id is None:
            raise ValueError("A case is required before exporting a report")
        return ForensicReportGenerator(self.database).generate(
            self.case_id,
            output_path,
        )

    def _on_parse_finished(self, result):
        if result is None:
            self.statusBar().showMessage("Operation failed.")
            return

        self.statusBar().showMessage(
            f"Completed: {result['events']:,} events processed."
        )
        self.refresh()

    def _on_worker_error(self, message):
        QMessageBox.critical(self, "Forensic Operation Failed", message)

    def _on_thread_finished(self):
        self._thread = None
        self._worker = None
        self._busy = False
        self.statusBar().showMessage("Ready.")
