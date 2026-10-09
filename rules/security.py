from models.event import Event
from rules.base import DetectionRule


class FailedLogonRule(DetectionRule):

    rule_id = "SEC-4625"
    title = "Failed Logon"
    description = "A failed Windows logon attempt was detected."
    severity = "medium"
    mitre_technique = "T1110"

    def matches(self, event: Event) -> bool:
        return event.event_id == 4625


class SuccessfulLogonRule(DetectionRule):

    rule_id = "SEC-4624"
    title = "Successful Logon"
    description = "A successful Windows logon was detected."
    severity = "low"
    mitre_technique = None

    def matches(self, event: Event) -> bool:
        return event.event_id == 4624


class ProcessCreationRule(DetectionRule):

    rule_id = "SEC-4688"
    title = "Process Creation"
    description = "A new process was created on the system."
    severity = "medium"
    mitre_technique = "T1059"

    def matches(self, event: Event) -> bool:
        return event.event_id == 4688


class SpecialPrivilegesRule(DetectionRule):

    rule_id = "SEC-4672"
    title = "Special Privileges Assigned"
    description = "Special privileges were assigned to a new logon."
    severity = "high"
    mitre_technique = "T1078"

    def matches(self, event: Event) -> bool:
        return event.event_id == 4672