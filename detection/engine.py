from typing import Iterable

from models.event import Event
from rules.base import DetectionRule
from findings.finding import Finding
from intelligence.mitre import MitreMapper


class DetectionEngine:

    def __init__(self, rules: list[DetectionRule]):
        self.rules = rules

    def analyze(
        self,
        events: Iterable[Event],
        case_id: str | None = None
    ) -> list[Finding]:

        findings = []

        for event in events:

            for rule in self.rules:

                if not rule.matches(event):
                    continue

                mitre_technique = MitreMapper.get_technique_id(
                    rule.rule_id
                )

                finding = Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    timestamp=event.timestamp,
                    event_id=event.event_id,
                    record_id=event.record_id,
                    channel=event.channel,
                    computer=event.computer,
                    user=event.user,
                    evidence_id=event.evidence_id,
                    case_id=case_id,
                    mitre_technique=mitre_technique,
                )

                findings.append(finding)

        return findings