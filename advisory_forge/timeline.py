"""Coordinated-disclosure timeline generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta


@dataclass(frozen=True)
class TimelineEvent:
    """One dated disclosure milestone."""

    date: date
    offset_days: int
    label: str
    reminder: bool = False


def generate_timeline(reported: str, publication_days: int = 90) -> list[TimelineEvent]:
    """Return a 90-day coordinated-disclosure schedule for *reported*.

    Milestones after ``publication_days`` are omitted so a shorter negotiated
    embargo remains coherent.
    """
    try:
        reported_date = date.fromisoformat(reported)
    except ValueError as exc:
        raise ValueError("reported date must use YYYY-MM-DD format") from exc
    if publication_days <= 0:
        raise ValueError("publication_days must be positive")

    definitions = (
        (0, "Initial report sent to vendor", False),
        (7, "Vendor acknowledgment expected; follow up if silent", True),
        (14, "First remediation status nudge", True),
        (30, "Coordination checkpoint: progress, ETA, and blockers", True),
        (60, "Publication deadline warning and extension decision", True),
        (publication_days, "Coordinated advisory publication target", False),
    )
    events: list[TimelineEvent] = []
    for offset, label, reminder in definitions:
        if offset > publication_days:
            continue
        events.append(TimelineEvent(reported_date + timedelta(days=offset), offset, label, reminder))
    return events


def render_timeline(events: list[TimelineEvent]) -> str:
    """Render timeline events as a Markdown table suitable for an advisory."""
    lines = ["| Date | Offset | Event |", "|---|---:|---|"]
    for event in events:
        reminder = " *(escalation reminder)*" if event.reminder else ""
        lines.append(f"| {event.date.isoformat()} | +{event.offset_days}d | {event.label}{reminder} |")
    return "\n".join(events and lines or lines[:2])
