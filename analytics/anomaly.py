from collections import Counter
from models.event import Event


class AnomalyDetector:

    def detect(self, events: list[Event]) -> list[dict]:
        event_counts = Counter()

        for event in events:
            if event.event_id is not None:
                event_counts[event.event_id] += 1

        anomalies = []

        for event_id, count in event_counts.items():
            if count >= 1000:
                matching_events = [
                    event for event in events
                    if event.event_id == event_id
                ]
                anomalies.append({
                    "type": "High Event Frequency",
                    "event_id": event_id,
                    "count": count,
                    "events": matching_events,
                    "description": (
                        f"Event ID {event_id} occurred "
                        f"{count} times."
                    ),
                })

        return anomalies