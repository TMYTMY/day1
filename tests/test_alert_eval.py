"""The pure half of a fire: the verdict, the window, and the fire key.

Nothing in these tests touches a database, a clock or a network. That is the
point of the module under test: a comparison that needs any of those cannot be
replayed, and an alert whose number cannot be replayed cannot be defended.
"""

from __future__ import annotations

import inspect
from datetime import date, datetime, timedelta, timezone

import pytest

import src.alert_eval as alert_eval
from src.alert_eval import (
    ABOVE_ABSOLUTE,
    BELOW_ABSOLUTE,
    CHANGE_PCT_DOWN,
    CHANGE_PCT_UP,
    COMPARISONS,
    FIRE,
    INSUFFICIENT_DATA,
    NO_FIRE,
    VERDICTS,
    Window,
    evaluate,
    fire_key,
    window_for,
)
from src.alerts import COMPARISONS as DEFINITION_COMPARISONS


def _local(year: int, month: int, day: int, hour: int, minute: int = 0) -> datetime:
    """A time in the instance's local time, whatever this machine's zone is.

    Building the wall clock first and converting after keeps the expectation
    ("ten past ten local") true on a laptop in Hong Kong and a server in UTC.
    """
    return datetime(year, month, day, hour, minute).astimezone()


# --- the comparison -------------------------------------------------------


@pytest.mark.parametrize(
    "value, previous, comparison, constant, verdict",
    [
        # below_absolute: strict, so the constant itself does not fire.
        (99.0, None, BELOW_ABSOLUTE, 100.0, FIRE),
        (100.0, None, BELOW_ABSOLUTE, 100.0, NO_FIRE),
        (101.0, None, BELOW_ABSOLUTE, 100.0, NO_FIRE),
        # above_absolute: strict the other way.
        (101.0, None, ABOVE_ABSOLUTE, 100.0, FIRE),
        (100.0, None, ABOVE_ABSOLUTE, 100.0, NO_FIRE),
        (99.0, None, ABOVE_ABSOLUTE, 100.0, NO_FIRE),
        # change_pct_down: the threshold is a distance, and it is reached, not crossed.
        (87.5, 100.0, CHANGE_PCT_DOWN, 12.5, FIRE),
        (87.6, 100.0, CHANGE_PCT_DOWN, 12.5, NO_FIRE),
        (120.0, 100.0, CHANGE_PCT_DOWN, 12.5, NO_FIRE),
        # change_pct_up, and an increase measured from a negative base is a rise.
        (112.5, 100.0, CHANGE_PCT_UP, 12.5, FIRE),
        (112.0, 100.0, CHANGE_PCT_UP, 12.5, NO_FIRE),
        (-80.0, -100.0, CHANGE_PCT_UP, 12.5, FIRE),
        (-120.0, -100.0, CHANGE_PCT_DOWN, 12.5, FIRE),
        # A zero previous value has no percentage change. It is not an infinite
        # rise and not a 100% fall.
        (10.0, 0.0, CHANGE_PCT_UP, 12.5, INSUFFICIENT_DATA),
        (0.0, 0.0, CHANGE_PCT_DOWN, 12.5, INSUFFICIENT_DATA),
    ],
)
def test_every_comparison_kind_has_one_defined_verdict(
    value, previous, comparison, constant, verdict
):
    assert evaluate(value, previous, comparison, constant) == verdict


@pytest.mark.parametrize("comparison", COMPARISONS)
def test_a_missing_value_is_never_reported_as_a_healthy_one(comparison):
    """An absent sum is not a sum of zero, for every comparison kind."""
    assert evaluate(None, 100.0, comparison, 10.0) == INSUFFICIENT_DATA


@pytest.mark.parametrize("comparison", (CHANGE_PCT_DOWN, CHANGE_PCT_UP))
def test_a_percentage_without_a_previous_value_is_insufficient_data(comparison):
    assert evaluate(100.0, None, comparison, 12.5) == INSUFFICIENT_DATA


def test_the_verdict_vocabulary_is_exactly_three_words():
    assert VERDICTS == (FIRE, NO_FIRE, INSUFFICIENT_DATA)
    assert set(VERDICTS) == {"fire", "no_fire", "insufficient_data"}


def test_an_unknown_comparison_is_refused_rather_than_guessed():
    with pytest.raises(ValueError, match="Unknown comparison"):
        evaluate(1.0, 1.0, "below_a_bit", 1.0)


def test_a_constant_that_is_not_a_finite_number_is_refused():
    for constant in (float("nan"), float("inf"), "12.5", True):
        with pytest.raises(ValueError, match="constant"):
            evaluate(1.0, 1.0, ABOVE_ABSOLUTE, constant)  # type: ignore[arg-type]


def test_the_comparison_is_pure_deterministic_and_takes_nothing_else():
    """No clock, no database, no model: four arguments, one of three answers."""
    parameters = list(inspect.signature(evaluate).parameters)
    assert parameters == ["value", "previous", "comparison", "constant"]

    calls = {evaluate(87.5, 100.0, CHANGE_PCT_DOWN, 12.5) for _ in range(50)}
    assert calls == {FIRE}

    # The module that decides a fire imports nothing that can read the world.
    imported = {name for name in vars(alert_eval) if not name.startswith("_")}
    assert not imported & {"sqlite3", "requests", "openai", "datetime_now"}


def test_the_definition_vocabulary_and_the_comparison_vocabulary_are_the_same():
    """A kind a draft may store is a kind a fire can decide, and no other."""
    assert DEFINITION_COMPARISONS == COMPARISONS


# --- the window -----------------------------------------------------------


def test_the_window_ends_on_the_last_complete_day_before_the_fire_date():
    window = window_for(_local(2026, 10, 28, 10, 0), "09:00", 7)
    assert window.fire_date == date(2026, 10, 28)
    assert window.end == date(2026, 10, 27)
    assert window.start == date(2026, 10, 21)
    assert window.days == 7


def test_before_the_local_time_the_most_recent_due_period_is_yesterdays():
    window = window_for(_local(2026, 10, 28, 8, 59), "09:00", 1)
    assert window.fire_date == date(2026, 10, 27)
    assert window.end == date(2026, 10, 26)
    assert window.start == date(2026, 10, 26)


def test_the_local_time_itself_is_due():
    window = window_for(_local(2026, 10, 28, 9, 0), "09:00", 1)
    assert window.fire_date == date(2026, 10, 28)
    assert window.end == date(2026, 10, 27)


def test_two_ticks_in_the_same_period_resolve_the_same_window():
    """Which is what lets the fire key be the duplicate guard."""
    morning = window_for(_local(2026, 10, 28, 9, 30), "09:00", 30)
    evening = window_for(_local(2026, 10, 28, 23, 59), "09:00", 30)
    assert morning == evening


def test_the_window_is_the_number_of_days_the_definition_asked_for():
    for days in (1, 7, 30, 365):
        window = window_for(_local(2026, 10, 28, 10, 0), "09:00", days)
        assert window.days == days
        assert window.start == window.end - timedelta(days=days - 1)


def test_a_window_shorter_than_a_day_is_refused():
    with pytest.raises(ValueError, match="at least 1 day"):
        window_for(_local(2026, 10, 28, 10, 0), "09:00", 0)


def test_a_local_time_that_is_not_a_clock_time_is_refused():
    for value in ("9am", "24:00", "09:60", ""):
        with pytest.raises(ValueError, match="24-hour"):
            window_for(_local(2026, 10, 28, 10, 0), value, 7)


def test_a_utc_time_is_read_in_the_local_zone_of_the_machine():
    """The schedule is a local time, so the conversion happens before the date."""
    utc = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
    window = window_for(utc, "00:00", 1)
    expected = utc.astimezone().date()
    assert window.fire_date == expected


# --- the fire key ---------------------------------------------------------


def test_the_fire_key_is_the_definition_identity_and_the_window_end():
    assert fire_key(7, date(2026, 10, 27)) == "alert:7:2026-10-27"


def test_the_fire_key_is_stable_across_calls_and_processes():
    first = fire_key(7, date(2026, 10, 27))
    second = fire_key(7, date(2026, 10, 27))
    assert first == second
    assert first == "alert:7:2026-10-27"


def test_each_identity_and_each_window_has_its_own_fire_key():
    keys = {
        fire_key(7, date(2026, 10, 27)),
        fire_key(7, date(2026, 10, 26)),
        fire_key(8, date(2026, 10, 27)),
        # A superseding definition is a new row, so it may evaluate the same
        # window itself without colliding with the definition it replaced.
        fire_key(9, date(2026, 10, 27)),
    }
    assert len(keys) == 4


def test_a_window_is_an_inclusive_range_of_days():
    window = Window(fire_date=date(2026, 10, 28), start=date(2026, 10, 21), end=date(2026, 10, 27))
    assert window.start <= window.end < window.fire_date
