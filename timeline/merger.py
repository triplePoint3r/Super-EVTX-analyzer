from heapq import heappush, heappop
from pathlib import Path
from typing import Iterator, List

from models.event import Event
from parsers.evtx_parser import EvtxParser


class TimelineMerger:
    """
    Merge events from multiple EVTX files into one
    chronologically sorted timeline.
    """

    def __init__(self):
        self.parser = EvtxParser()

    def _load_sorted_events(
        self,
        evtx_file: Path,
        evidence_id: str | None = None
    ) -> List[Event]:

        events = list(
            self.parser.parse(
                evtx_file,
                evidence_id=evidence_id
            )
        )

        events.sort(
            key=lambda event: event.timestamp
        )

        return events

    def merge(
        self,
        evtx_files: List[Path],
        evidence_id: str | None = None,
        case_id: str | None = None,
    ) -> Iterator[Event]:

        event_lists = []

        for evtx_file in evtx_files:

            events = self._load_sorted_events(
                evtx_file,
                evidence_id=evidence_id
            )

            for event in events:
                event.case_id = case_id

            event_lists.append(events)

        heap = []

        # Put the first event from every file
        for index, events in enumerate(event_lists):

            if not events:
                continue

            event = events[0]

            if event.timestamp is not None:
                heappush(
                    heap,
                    (
                        event.timestamp,
                        index,
                        0,
                        event
                    )
                )

        # Merge sorted event lists
        while heap:

            _, file_index, event_index, event = heappop(heap)

            yield event

            next_index = event_index + 1

            if next_index >= len(event_lists[file_index]):
                continue

            next_event = event_lists[file_index][next_index]

            if next_event.timestamp is not None:

                heappush(
                    heap,
                    (
                        next_event.timestamp,
                        file_index,
                        next_index,
                        next_event
                    )
                )