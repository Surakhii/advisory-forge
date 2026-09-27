from datetime import date

import pytest

from advisory_forge.timeline import generate_timeline, render_timeline


def test_default_timeline_uses_ninety_day_deadline() -> None:
    events = generate_timeline("2026-03-30")
    assert [(event.offset_days, event.date) for event in events] == [
        (0, date(2026, 3, 30)),
        (7, date(2026, 4, 6)),
        (14, date(2026, 4, 13)),
        (30, date(2026, 4, 29)),
        (60, date(2026, 5, 29)),
        (90, date(2026, 6, 28)),
    ]
    assert events[-1].label == "Coordinated advisory publication target"
    assert sum(event.reminder for event in events) == 4


def test_shorter_publication_window_skips_later_milestones() -> None:
    events = generate_timeline("2026-01-01", publication_days=21)
    assert [event.offset_days for event in events] == [0, 7, 14, 21]


def test_render_timeline_is_markdown() -> None:
    rendered = render_timeline(generate_timeline("2026-03-30"))
    assert rendered.startswith("| Date | Offset | Event |")
    assert "| 2026-04-06 | +7d | Vendor acknowledgment expected; follow up if silent *(escalation reminder)* |" in rendered


@pytest.mark.parametrize(("reported", "publication_days"), [("30/03/2026", 90), ("2026-03-30", 0)])
def test_invalid_timeline_inputs(reported: str, publication_days: int) -> None:
    with pytest.raises(ValueError):
        generate_timeline(reported, publication_days)
