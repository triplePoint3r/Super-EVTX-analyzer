class RiskScorer:

    SCORES = {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 100,
    }

    def score_finding(self, finding) -> int:
        return self.SCORES.get(
            finding.severity.lower(),
            0
        )

    def score_findings(self, findings) -> list[dict]:
        results = []

        for finding in findings:
            score = self.score_finding(finding)

            results.append({
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": score,
                "mitre_technique": finding.mitre_technique,
                "event_id": finding.event_id,
                "user": finding.user,
                "computer": finding.computer,
            })

        return results

    def explain_case_score(
        self,
        findings,
        correlations=None,
        anomalies=None,
        iocs=None,
    ) -> dict:
        if not findings:
            return {
                "base_score": 0,
                "finding_bonus": 0,
                "correlation_bonus": 0,
                "anomaly_bonus": 0,
                "ioc_bonus": 0,
                "score": 0,
            }

        scores = [
            self.score_finding(finding)
            for finding in findings
        ]
        base_score = max(scores)
        finding_bonus = min(10, max(0, len(findings) - 1) * 2)
        correlation_bonus = min(10, len(correlations or []) * 5)
        anomaly_bonus = min(10, len(anomalies or []) * 5)
        ioc_bonus = 5 if iocs else 0

        score = min(
            100,
            base_score
            + finding_bonus
            + correlation_bonus
            + anomaly_bonus
            + ioc_bonus,
        )
        return {
            "base_score": base_score,
            "finding_bonus": finding_bonus,
            "correlation_bonus": correlation_bonus,
            "anomaly_bonus": anomaly_bonus,
            "ioc_bonus": ioc_bonus,
            "score": score,
        }

    def calculate_case_score(
        self,
        findings,
        correlations=None,
        anomalies=None,
        iocs=None,
    ) -> int:
        return self.explain_case_score(
            findings,
            correlations=correlations,
            anomalies=anomalies,
            iocs=iocs,
        )["score"]

    def get_risk_level(self, score: int) -> str:
        if score >= 90:
            return "critical"

        if score >= 70:
            return "high"

        if score >= 40:
            return "medium"

        if score > 0:
            return "low"

        return "none"