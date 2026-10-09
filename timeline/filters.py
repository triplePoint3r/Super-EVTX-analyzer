from datetime import datetime
from typing import Iterable, Iterator, Optional, Set

from models.event import Event


class TimelineFilter:
    """
    Filter Event objects based on investigation criteria.
    """

    def filter(
        self,
        events: Iterable[Event],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        channels: Optional[Set[str]] = None,
        event_ids: Optional[Set[int]] = None,
        computers: Optional[Set[str]] = None,
        users: Optional[Set[str]] = None,
        providers: Optional[Set[str]] = None,
    ) -> Iterator[Event]:

        for event in events:

            # Time range
            if start_time is not None:
                if event.timestamp is None:
                    continue

                if event.timestamp < start_time:
                    continue

            if end_time is not None:
                if event.timestamp is None:
                    continue

                if event.timestamp > end_time:
                    continue

            # Channel
            if channels is not None:
                if event.channel not in channels:
                    continue

            # Event ID
            if event_ids is not None:
                if event.event_id not in event_ids:
                    continue

            # Computer
            if computers is not None:
                if event.computer not in computers:
                    continue

            # User
            if users is not None:
                if event.user not in users:
                    continue

            # Provider
            if providers is not None:
                if event.provider not in providers:
                    continue

            yield event