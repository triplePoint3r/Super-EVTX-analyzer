from abc import ABC, abstractmethod

from models.event import Event


class DetectionRule(ABC):

    rule_id: str
    title: str
    description: str
    severity: str
    mitre_technique: str | None = None

    @abstractmethod
    def matches(self, event: Event) -> bool:
        pass