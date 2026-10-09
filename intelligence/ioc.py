import re
import ipaddress
from typing import Iterable
from models.event import Event


class IOCExtractor:

    IP_PATTERN = re.compile(
        r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        r"(?<![A-Za-z0-9])[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]+(?![A-Za-z0-9]))"
    )

    DOMAIN_PATTERN = re.compile(
    r"\b(?=[a-zA-Z0-9.-]*[a-zA-Z])"
    r"(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|net|org|edu|gov|mil|io|co|info|biz|me|tv|xyz)\b",
    re.IGNORECASE
    )

    HASH_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{32}\b"
        r"|\b[a-fA-F0-9]{40}\b"
        r"|\b[a-fA-F0-9]{64}\b"
    )

    def extract_from_event(self, event: Event) -> dict:
        text = " ".join(
            [
                event.raw_xml or "",
                str(event.event_data or {})
            ]
        )

        return {
            "ips": self._extract_ips(text),
            "domains": self._extract(self.DOMAIN_PATTERN, text, normalize=True),
            "hashes": self._extract(self.HASH_PATTERN, text, normalize=True),
        }

    def extract(self, events: Iterable[Event]) -> list[dict]:
        results = []

        for event in events:
            iocs = self.extract_from_event(event)

            if any(iocs.values()):
                results.append({
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                    "record_id": event.record_id,
                    "evidence_id": event.evidence_id,
                    "event": event,
                    "iocs": iocs,
                })

        return results

    @staticmethod
    def _extract(pattern, text: str, normalize: bool = False) -> list[str]:
        values = pattern.findall(text)
        if normalize:
            values = [value.lower() for value in values]
        return sorted(set(values))

    @classmethod
    def _extract_ips(cls, text: str) -> list[str]:
        values = []
        for candidate in cls.IP_PATTERN.findall(text):
            try:
                values.append(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        return sorted(set(values))