import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

from models.event import Event


class TimelineAnalyzer:
    """
    Analyze a normalized Event timeline.
    """

    def analyze(
        self,
        events: Iterable[Event],
        output_csv: Optional[Path] = None,
        output_stats: Optional[Path] = None,
    ) -> dict:

        stats = {
            "total_events": 0,
            "channels": Counter(),
            "event_ids": Counter(),
            "computers": Counter(),
            "providers": Counter(),
            "users": Counter(),
            "levels": Counter(),
            "time_range": {
                "start": None,
                "end": None,
            },
        }

        csv_file = None
        csv_writer = None

        try:
            # ==========================================
            # CSV
            # ==========================================

            if output_csv is not None:

                output_csv = Path(output_csv)
                output_csv.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                csv_file = open(
                    output_csv,
                    "w",
                    newline="",
                    encoding="utf-8"
                )

                csv_writer = csv.writer(csv_file)

                csv_writer.writerow([
                    "Timestamp",
                    "Channel",
                    "Event ID",
                    "Level",
                    "Computer",
                    "Provider",
                    "Record ID",
                    "User",
                    "Database Event ID",
                    "Case ID",
                    "Evidence ID",
                    "Event Data",
                ])

            # ==========================================
            # Process Events
            # ==========================================

            for event in events:

                stats["total_events"] += 1

                # --------------------------
                # Counters
                # --------------------------

                if event.channel:
                    stats["channels"][event.channel] += 1

                if event.event_id is not None:
                    stats["event_ids"][str(event.event_id)] += 1

                if event.computer:
                    stats["computers"][event.computer] += 1

                if event.provider:
                    stats["providers"][event.provider] += 1

                if event.user:
                    stats["users"][event.user] += 1

                if event.level:
                    stats["levels"][event.level] += 1

                # --------------------------
                # Time range
                # --------------------------

                if event.timestamp is not None:

                    timestamp = event.timestamp.isoformat()

                    if stats["time_range"]["start"] is None:
                        stats["time_range"]["start"] = timestamp

                    stats["time_range"]["end"] = timestamp

                # --------------------------
                # CSV
                # --------------------------

                if csv_writer:

                    timestamp = ""

                    if event.timestamp is not None:
                        timestamp = event.timestamp.strftime(
                            "%Y-%m-%d %H:%M:%S.%f"
                        )[:-3]

                    description = "; ".join(
                        f"{name}={value}"
                        for name, value in event.event_data.items()
                    )

                    csv_writer.writerow([
                        timestamp,
                        event.channel or "",
                        event.event_id or "",
                        event.level or "",
                        event.computer or "",
                        event.provider or "",
                        event.record_id or "",
                        event.user or "",
                        event.db_id or "",
                        event.case_id or "",
                        event.evidence_id or "",
                        description,
                    ])

            # ==========================================
            # Convert Counters
            # ==========================================

            stats["channels"] = dict(
                stats["channels"].most_common()
            )

            stats["event_ids"] = dict(
                stats["event_ids"].most_common()
            )

            stats["computers"] = dict(
                stats["computers"].most_common()
            )

            stats["providers"] = dict(
                stats["providers"].most_common()
            )

            stats["users"] = dict(
                stats["users"].most_common()
            )

            stats["levels"] = dict(
                stats["levels"].most_common()
            )

            # ==========================================
            # Save JSON
            # ==========================================

            if output_stats is not None:

                output_stats = Path(output_stats)

                output_stats.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                with open(
                    output_stats,
                    "w",
                    encoding="utf-8"
                ) as stats_file:

                    json.dump(
                        stats,
                        stats_file,
                        indent=4,
                        ensure_ascii=False
                    )

            return stats

        finally:

            if csv_file is not None:
                csv_file.close()