import re
from typing import Iterable
from models.event import Event


class EntityExtractor:

    USER_PATTERN = re.compile(
        r"\b(?:UserName|TargetUserName|SubjectUserName|AccountName)"
        r"[=:]\s*([A-Za-z0-9._$-]+)",
        re.IGNORECASE
    )

    COMPUTER_PATTERN = re.compile(
        r"\b(?:Computer|ComputerName)"
        r"[=:]\s*([A-Za-z0-9._$-]+)",
        re.IGNORECASE
    )

    PROCESS_PATTERN = re.compile(
    r"(?:ProcessName|NewProcessName|Image)"
    r"[=:]\s*['\"]?([^,'\"}]+)",
    re.IGNORECASE
    )

    def extract_from_event(self, event: Event) -> dict:
        users = set()
        computers = set()
        processes = set()

        # User
        if event.user:
            users.add(event.user)

        for key in (
            "UserName",
            "TargetUserName",
            "SubjectUserName",
            "AccountName",
        ):
            value = event.event_data.get(key)
            if value:
                users.add(str(value))

        # Computer
        if event.computer:
            computers.add(event.computer)

        for key in (
            "Computer",
            "ComputerName",
        ):
            value = event.event_data.get(key)
            if value:
                computers.add(str(value))

        # Process
        for key in (
            "ProcessName",
            "NewProcessName",
            "Image",
        ):
            value = event.event_data.get(key)
            if value:
                processes.add(str(value))

        return {
            "users": sorted(users),
            "computers": sorted(computers),
            "processes": sorted(processes),
        }

    def extract(self, events: Iterable[Event]) -> list[dict]:
        results = []

        for event in events:
            entities = self.extract_from_event(event)

            if any(entities.values()):
                results.append({
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                    "record_id": event.record_id,
                    "evidence_id": event.evidence_id,
                    "event": event,
                    "entities": entities,
                })

        return results