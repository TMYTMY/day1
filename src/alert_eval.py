"""What a fire is decided by: a window, a fire key, and a pure comparison.

Everything here is data and arithmetic. There is no clock, no database, no
mail, and no language model, so the same value, previous value, comparison and
constant always produce the same verdict, on any machine, on any day. A caller
that needs the time passes it in; a caller that needs a number reads it
somewhere else. That separation is what makes an evaluation replayable months
later (see ``docs/adr/0003-model-authors-definitions-not-execution.md``).

The three verdicts are the whole vocabulary of an evaluation:

* ``fire`` — the comparison was met, so the fire notifies.
* ``no_fire`` — the comparison was not met. The fire is still recorded.
* ``insufficient_data`` — the comparison could not be made, because the value
  or the previous value is missing. It is never reported as ``no_fire``: a
  missing number is not a healthy one, and a percentage change from nothing is
  not zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta

# --- comparisons ----------------------------------------------------------

# Comparison kinds. An unknown kind is refused when a definition is written,
# so this module never has to guess what one means.
BELOW_ABSOLUTE = "below_absolute"
ABOVE_ABSOLUTE = "above_absolute"
CHANGE_PCT_DOWN = "change_pct_down"
CHANGE_PCT_UP = "change_pct_up"
COMPARISONS = (BELOW_ABSOLUTE, ABOVE_ABSOLUTE, CHANGE_PCT_DOWN, CHANGE_PCT_UP)

PERCENTAGE_COMPARISONS = (CHANGE_PCT_DOWN, CHANGE_PCT_UP)

# --- verdicts -------------------------------------------------------------

FIRE = "fire"
NO_FIRE = "no_fire"
INSUFFICIENT_DATA = "insufficient_data"
VERDICTS = (FIRE, NO_FIRE, INSUFFICIENT_DATA)


def evaluate(value: object, previous: object, comparison: str, constant: float) -> str:
    """Compare one window's value with its constant. Pure, and total.

    ``value`` is the metric over the resolved window; ``previous`` is the value
    of the last window that had one, and is only read by a percentage
    comparison. A missing ``value`` is ``insufficient_data`` for every kind of
    comparison, because an absent sum is not a sum of zero.

    An absolute comparison is strict: ``below_absolute`` fires when the value
    is under the constant, not when it equals it. A percentage comparison fires
    once the change reaches the constant: 15% down is a fire for a 12.5%
    threshold.
    """
    if comparison not in COMPARISONS:
        raise ValueError(f"Unknown comparison: {comparison!r}")
    threshold = _number(constant, "constant")
    if value is None:
        return INSUFFICIENT_DATA
    current = _number(value, "value")

    if comparison == BELOW_ABSOLUTE:
        return FIRE if current < threshold else NO_FIRE
    if comparison == ABOVE_ABSOLUTE:
        return FIRE if current > threshold else NO_FIRE

    if previous is None:
        return INSUFFICIENT_DATA
    earlier = _number(previous, "previous")
    if earlier == 0:
        # A change from zero has no percentage. Dividing would invent one.
        return INSUFFICIENT_DATA
    change = (current - earlier) / abs(earlier) * 100.0
    if comparison == CHANGE_PCT_DOWN:
        return FIRE if change <= -threshold else NO_FIRE
    return FIRE if change >= threshold else NO_FIRE


def _number(value: object, field: str) -> float:
    """A finite float, or a ValueError naming the field that is not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"The {field} {value!r} is not a number.")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise ValueError(f"The {field} {value!r} is not a finite number.")
    return number


# --- the window a fire covers ---------------------------------------------


@dataclass(frozen=True)
class Window:
    """One period of data, resolved from the schedule.

    ``fire_date`` is the day the fire belongs to; ``start`` and ``end`` are
    inclusive calendar days of warehouse data. The window ends on the last
    complete day before the fire date, because a day that is still accumulating
    is not a period.
    """

    fire_date: date
    start: date
    end: date

    @property
    def days(self) -> int:
        return (self.end - self.start).days + 1


def window_for(now: datetime, local_time: str, window_days: int) -> Window:
    """The window a daily fire at ``local_time`` covers, as of ``now``.

    ``local_time`` is the definition's own ``HH:MM``, read in the instance's
    local time. Before that time of day the most recent due period is
    yesterday's; at or after it, today's. Nothing is stored, so two ticks in the
    same period resolve the same window — which is what makes the fire key a
    duplicate guard rather than a hope.
    """
    if window_days < 1:
        raise ValueError(f"A window must be at least 1 day, not {window_days}.")
    hour, minute = _clock(local_time)

    local = now.astimezone()
    fire_date = local.date()
    if (local.hour, local.minute) < (hour, minute):
        fire_date -= timedelta(days=1)

    end = fire_date - timedelta(days=1)
    return Window(fire_date=fire_date, start=end - timedelta(days=window_days - 1), end=end)


def _clock(local_time: str) -> tuple[int, int]:
    parts = (local_time or "").strip().split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError(f"The local time {local_time!r} is not a 24-hour HH:MM value.")
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"The local time {local_time!r} is not a 24-hour HH:MM value.")
    return hour, minute


def fire_key(alert_id: int, window_end: date) -> str:
    """The uniqueness key of a fire: the definition's identity plus its window end.

    A definition's identity is its row id: supersession writes a new row and
    retires the old one, so a replacing definition is a different identity and
    may evaluate the same period itself. The window end, not the fire date, is
    the second half of the key, because the window is what is evaluated.
    """
    return f"alert:{int(alert_id)}:{window_end.isoformat()}"
