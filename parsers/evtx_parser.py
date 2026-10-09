from pathlib import Path
from datetime import datetime
from typing import Iterator, Optional
import xml.etree.ElementTree as ET
import logging

from Evtx.Evtx import Evtx

from models.event import Event


logger = logging.getLogger(__name__)


class EvtxParser:
    """
    Parse Windows EVTX files into normalized Event objects.
    """

    def parse(self, evtx_path: Path, evidence_id: Optional[str] = None) -> Iterator[Event]:
        """
        Parse an EVTX file and yield Event objects one by one.

        Parameters:
            evtx_path: Path to the .evtx file.
            evidence_id: Optional ID linking events to their evidence.

        Yields:
            Event objects.
        """

        evtx_path = Path(evtx_path)

        if not evtx_path.exists():
            raise FileNotFoundError(f"EVTX file not found: {evtx_path}")

        if evtx_path.suffix.lower() != ".evtx":
            raise ValueError(f"Invalid evidence file: {evtx_path}")

        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                xml_string = record.xml()

                event = self._parse_event_xml(
                    xml_string,
                    evidence_id=evidence_id
                )

                if event is not None:
                    yield event

    def _parse_event_xml(
        self,
        xml_string: str,
        evidence_id: Optional[str] = None
    ) -> Optional[Event]:
        """
        Convert one Windows Event XML record into an Event object.
        """

        try:
            root = ET.fromstring(xml_string)

            system = self._find_child(root, "System")

            if system is None:
                return None

            # ==================== Time ====================

            timestamp = None

            time_created = self._find_child(system, "TimeCreated")

            if time_created is not None:
                system_time = time_created.get("SystemTime")

                if system_time:
                    timestamp = self._parse_timestamp(system_time)

            if timestamp is None:
                return None

            # ==================== Event ID ====================

            event_id = self._find_child(system, "EventID")

            event_id_value = None

            if event_id is not None and event_id.text:
                try:
                    event_id_value = int(event_id.text.strip())
                except ValueError:
                    event_id_value = None

            # ==================== Channel ====================

            channel = self._get_text(system, "Channel")

            # ==================== Computer ====================

            computer = self._get_text(system, "Computer")

            # ==================== Provider ====================

            provider = self._find_child(system, "Provider")

            provider_name = None

            if provider is not None:
                provider_name = provider.get("Name")

            # ==================== Record ID ====================

            record_id = self._get_text(system, "EventRecordID")

            record_id_value = None

            if record_id:
                try:
                    record_id_value = int(record_id)
                except ValueError:
                    record_id_value = None

            # ==================== Level ====================

            level = self._get_text(system, "Level")

            level_value = self._normalize_level(level)

            # ==================== Event Data ====================

            parsed_event_data = self._parse_event_data(root)

            # ==================== User ====================

            user = self._extract_user(system, parsed_event_data)

            # ==================== Event ====================

            return Event(
                timestamp=timestamp,
                event_id=event_id_value,
                channel=channel,
                computer=computer,
                provider=provider_name,
                record_id=record_id_value,
                level=level_value,
                user=user,
                event_data=parsed_event_data,
                raw_xml=xml_string,
                evidence_id=evidence_id
            )

        except ET.ParseError as exc:
            logger.warning("Malformed EVTX event XML skipped: %s", exc)
            return None

        except (AttributeError, TypeError, ValueError) as exc:
            logger.warning("Unsupported EVTX event structure skipped: %s", exc)
            return None

    # ============================================================
    # XML Helpers
    # ============================================================

    @staticmethod
    def _find_child(parent, name):
        """
        Find a direct XML child regardless of namespace.
        """

        for child in parent:
            if child.tag.split("}")[-1] == name:
                return child

        return None

    @staticmethod
    def _get_text(parent, name):
        """
        Get text from a direct XML child.
        """

        element = EvtxParser._find_child(parent, name)

        if element is not None and element.text:
            return element.text.strip()

        return None

    # ============================================================
    # Timestamp
    # ============================================================

    @staticmethod
    def _parse_timestamp(value: str) -> Optional[datetime]:
        """
        Parse Windows EVTX SystemTime.

        Example:
            2026-10-08T10:30:15.1234567Z
        """

        value = value.strip()

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        # Python supports up to 6 fractional digits.
        if "." in value:
            before, after = value.split(".", 1)

            timezone = ""

            if "+" in after:
                fraction, timezone = after.split("+", 1)
                timezone = "+" + timezone

            elif "-" in after:
                fraction, timezone = after.split("-", 1)
                timezone = "-" + timezone

            else:
                fraction = after

            fraction = fraction[:6]

            value = f"{before}.{fraction}{timezone}"

        try:
            return datetime.fromisoformat(value)

        except ValueError:
            return None

    # ============================================================
    # EventData
    # ============================================================

    @staticmethod
    def _parse_event_data(root) -> dict:
        """
        Extract EventData into:

            {
                "TargetUserName": "admin",
                "IpAddress": "192.168.1.10",
                ...
            }
        """

        event_data = None

        for element in root.iter():
            if element.tag.split("}")[-1] == "EventData":
                event_data = element
                break

        if event_data is None:
            return {}

        result = {}

        unnamed_index = 0

        for data in event_data:

            if data.tag.split("}")[-1] != "Data":
                continue

            name = data.get("Name")
            value = data.text or ""

            value = value.strip()

            if name:
                result[name] = value
            else:
                result[f"_unnamed_{unnamed_index}"] = value
                unnamed_index += 1

        return result

    # ============================================================
    # User
    # ============================================================

    @staticmethod
    def _extract_user(system, event_data: dict) -> Optional[str]:
        """
        Extract the most useful username available.
        """

        username_fields = (
            "SubjectUserName",
            "TargetUserName",
            "UserName",
            "AccountName",
        )

        for field in username_fields:

            value = event_data.get(field)

            if not value:
                continue

            value = value.strip()

            if value and value not in ("-", "N/A"):
                return value

        # Fallback to Security UserID
        security = EvtxParser._find_child(system, "Security")

        if security is not None:
            user_id = security.get("UserID")

            if user_id:
                return user_id

        return None

    # ============================================================
    # Level
    # ============================================================

    @staticmethod
    def _normalize_level(level: Optional[str]) -> Optional[str]:
        """
        Convert Windows numeric event levels into readable names.
        """

        levels = {
            "0": "LogAlways",
            "1": "Critical",
            "2": "Error",
            "3": "Warning",
            "4": "Information",
            "5": "Verbose",
        }

        if level is None:
            return None

        return levels.get(level, level)