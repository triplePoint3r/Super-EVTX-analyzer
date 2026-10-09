from models.event import Event


class InvestigationGraph:

    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, node_type: str, node_id: str, **attributes):
        key = f"{node_type}:{node_id}"

        if key not in self.nodes:
            self.nodes[key] = {
                "id": node_id,
                "type": node_type,
                "attributes": attributes,
            }

    def add_edge(
        self,
        source_type: str,
        source_id: str,
        relation: str,
        target_type: str,
        target_id: str,
    ):
        self.edges.append({
            "source": f"{source_type}:{source_id}",
            "relation": relation,
            "target": f"{target_type}:{target_id}",
        })

    def add_event(self, event: Event):
        if event.db_id is not None:
            event_id = str(event.db_id)
        else:
            event_id = f"record:{event.record_id}" if event.record_id is not None else "unpersisted"

        self.add_node(
            "event",
            event_id,
            event_id=event.event_id,
            db_id=event.db_id,
            evidence_id=event.evidence_id,
            case_id=event.case_id,
            record_id=event.record_id,
            timestamp=(
                event.timestamp.isoformat()
                if event.timestamp
                else None
            ),
        )

        if event.user:
            self.add_node("user", event.user)

            self.add_edge(
                "user",
                event.user,
                "generated",
                "event",
                event_id,
            )

        if event.computer:
            self.add_node("computer", event.computer)

            self.add_edge(
                "computer",
                event.computer,
                "recorded",
                "event",
                event_id,
            )

        if event.evidence_id:
            self.add_node("evidence", event.evidence_id)
            self.add_edge(
                "event",
                event_id,
                "belongs_to",
                "evidence",
                event.evidence_id,
            )

    def build(self, events: list[Event]) -> dict:
        for event in events:
            self.add_event(event)

        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

    def add_finding(self, finding):
        finding_id = str(
            getattr(finding, "db_id", None)
            or f"{finding.rule_id}:{finding.record_id}"
        )

        self.add_node(
            "finding",
            finding_id,
            title=finding.title,
            severity=finding.severity,
            rule_id=finding.rule_id,
        )

        if finding.user:
            self.add_node("user", finding.user)

            self.add_edge(
                "user",
                finding.user,
                "related_to",
                "finding",
                finding_id,
            )

        if finding.computer:
            self.add_node("computer", finding.computer)

            self.add_edge(
                "computer",
                finding.computer,
                "related_to",
                "finding",
                finding_id,
            )


    def add_iocs(self, event: Event, iocs: dict):
        event_id = (
            str(event.db_id)
            if event.db_id is not None
            else f"record:{event.record_id}"
        )

        for ip in iocs.get("ips", []):
            self.add_node("ip", ip)

            self.add_edge(
                "event",
                event_id,
                "contains",
                "ip",
                ip,
            )

        for domain in iocs.get("domains", []):
            self.add_node("domain", domain)

            self.add_edge(
                "event",
                event_id,
                "contains",
                "domain",
                domain,
            )

        for file_hash in iocs.get("hashes", []):
            self.add_node("hash", file_hash)

            self.add_edge(
                "event",
                event_id,
                "contains",
                "hash",
                file_hash,
            )

    def build_investigation(
        self,
        events: list[Event],
        findings: list,
        ioc_results: list[dict],
    ) -> dict:

        for event in events:
            self.add_event(event)

        for finding in findings:
            self.add_finding(finding)

        for finding in findings:
            self.add_finding_relationships(finding, events)

        for result in ioc_results:
            event = next(
                (
                    event
                    for event in events
                    if event.event_id == result["event_id"]
                    and event.evidence_id == result["evidence_id"]
                ),
                None,
            )

            if event:
                self.add_iocs(event, result["iocs"])

        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

    def add_finding_relationships(self, finding, events):
        finding_id = f"{finding.rule_id}:{finding.event_id}"

        event = next(
            (
                event
                for event in events
                if (
                    finding.record_id is not None
                    and event.record_id == finding.record_id
                )
                and (
                    finding.user is None
                    or event.user == finding.user
                )
                and (
                    finding.computer is None
                    or event.computer == finding.computer
                )
            ),
            None,
        )

        if event is None:
            return

        event_id = (
            str(event.db_id)
            if event.db_id is not None
            else f"record:{event.record_id}"
        )

        self.add_edge(
            "finding",
            finding_id,
            "detected_from",
            "event",
            event_id,
        )

        if finding.mitre_technique:
            self.add_node(
                "mitre",
                finding.mitre_technique,
            )

            self.add_edge(
                "finding",
                finding_id,
                "mapped_to",
                "mitre",
                finding.mitre_technique,
            )