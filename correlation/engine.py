from collections import defaultdict
from models.event import Event


class CorrelationEngine:

    def correlate(self, events: list[Event]) -> list[dict]:
        grouped = defaultdict(list)

        for event in events:
            if event.user:
                grouped[event.user].append(event)

        correlations = []

        for user, user_events in grouped.items():
            user_events.sort(
                key=lambda event: event.timestamp
                if event.timestamp is not None
                else 0
            )

            failed_logons = []
            successful_logons = []
            special_privileges = []

            for event in user_events:
                if event.event_id == 4625:
                    failed_logons.append(event)

                elif event.event_id == 4624:
                    successful_logons.append(event)

                elif event.event_id == 4672:
                    special_privileges.append(event)

            if failed_logons and successful_logons:
                ordered_events = sorted(
                    failed_logons + successful_logons,
                    key=lambda event: event.timestamp or 0,
                )
                correlations.append({
                    "type": "Failed-Then-Successful-Logon",
                    "user": user,
                    "failed_logons": failed_logons,
                    "successful_logons": successful_logons,
                    "events": ordered_events,
                    "event_roles": [
                        (
                            event,
                            "failed_logon" if event.event_id == 4625
                            else "successful_logon",
                        )
                        for event in ordered_events
                    ],
                })

            if successful_logons and special_privileges:
                ordered_events = sorted(
                    successful_logons + special_privileges,
                    key=lambda event: event.timestamp or 0,
                )
                correlations.append({
                    "type": "Successful-Logon-With-Special-Privileges",
                    "user": user,
                    "successful_logons": successful_logons,
                    "special_privileges": special_privileges,
                    "events": ordered_events,
                    "event_roles": [
                        (
                            event,
                            "successful_logon" if event.event_id == 4624
                            else "special_privilege",
                        )
                        for event in ordered_events
                    ],
                })

        return correlations