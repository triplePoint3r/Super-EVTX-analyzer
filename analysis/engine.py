from analytics.scoring import RiskScorer
from detection.engine import DetectionEngine
from correlation.engine import CorrelationEngine
from intelligence.ioc import IOCExtractor
from intelligence.entities import EntityExtractor
from analytics.anomaly import AnomalyDetector


class CaseAnalysisEngine:

    def __init__(self, detection_rules):
        self.risk_scorer = RiskScorer()
        self.detection_engine = DetectionEngine(detection_rules)
        self.correlation_engine = CorrelationEngine()
        self.ioc_extractor = IOCExtractor()
        self.entity_extractor = EntityExtractor()
        self.anomaly_detector = AnomalyDetector()

    def analyze(self, events, case_id=None):

        events = list(events)

        findings = self.detection_engine.analyze(
            events,
            case_id=case_id,
        )

        correlations = self.correlation_engine.correlate(
            events
        )

        iocs = self.ioc_extractor.extract(
            events
        )

        entities = self.entity_extractor.extract(
            events
        )

        anomalies = self.anomaly_detector.detect(
            events
        )

        risk_breakdown = self.risk_scorer.explain_case_score(
            findings,
            correlations=correlations,
            anomalies=anomalies,
            iocs=iocs,
        )
        risk_score = risk_breakdown["score"]
        risk_level = self.risk_scorer.get_risk_level(risk_score)

        return {
            "events": events,
            "findings": findings,
            "correlations": correlations,
            "iocs": iocs,
            "entities": entities,
            "anomalies": anomalies,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_breakdown": risk_breakdown,
        }