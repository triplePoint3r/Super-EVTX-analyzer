from collections import Counter
from typing import Iterable

from models.event import Event


def summarize_events(events: Iterable[Event]) -> dict:
    """Return deterministic, JSON-friendly event distribution statistics."""
    stats = {
        "total_events": 0,
        "channels": Counter(),
        "event_ids": Counter(),
        "computers": Counter(),
        "providers": Counter(),
        "users": Counter(),
        "levels": Counter(),
    }
    for event in events:
        stats["total_events"] += 1
        for field in ("channel", "computer", "provider", "user", "level"):
            value = getattr(event, field)
            if value:
                stats[f"{field}s" if field != "level" else "levels"][value] += 1
        if event.event_id is not None:
            stats["event_ids"][str(event.event_id)] += 1

    for key, value in stats.items():
        if isinstance(value, Counter):
            stats[key] = dict(value.most_common())
    return stats
