"""One instance's own record: who it is, and whether it can still deliver.

Both facts live in the instance settings database (``Settings.settings_path``)
and both are readable without the Fernet key, because both answer operational
questions rather than holding a secret:

* :class:`src.instance_identity.IdentityStore` — the UUID, hostname and path
  written at first configuration, and the check that refuses to deliver from a
  copy of the instance;
* :class:`src.delivery_health.DeliveryHealthStore` — one row per delivery
  attempt, and the ``never_sent`` / ``healthy`` / ``stale`` / ``failing``
  answer that a page renders.

This module is the seam that holds the two together against one path, with one
hostname, so the worker never passes a different path to each of them. A page
needs only :func:`src.delivery_health.delivery_health`; the identity check is
for anything that is about to send.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from src.delivery_health import (
    ATTEMPT_DELIVERED,
    ATTEMPT_FAILED,
    ATTEMPT_SUPPRESSED,
    DEFAULT_ALIVE_WINDOW,
    DeliveryHealth,
    DeliveryHealthStore,
)
from src.instance_identity import (
    IdentityCheck,
    IdentityStore,
    InstanceIdentity,
    running_hostname,
)

# The delivery statuses of a finished notification, mapped onto the health
# record's own vocabulary. ``not_wired`` and ``not_a_fire`` are absent on
# purpose: neither was offered to a server, so neither says anything about
# whether the mail path works.
HEALTH_OUTCOME_FOR_STATUS = {
    "delivered": ATTEMPT_DELIVERED,
    "suppressed": ATTEMPT_SUPPRESSED,
    "failed": ATTEMPT_FAILED,
}


class InstanceState:
    """The instance's identity, its delivery health, and the host in between."""

    def __init__(self, settings_path: Path, *, hostname: str | None = None):
        self.path = Path(settings_path)
        self.identity = IdentityStore(self.path)
        self.health = DeliveryHealthStore(self.path)
        # Injected by a test, and set from DAY1_INSTANCE_HOSTNAME in a
        # deployment whose hostname is not stable. None means "ask the host".
        self._hostname = (hostname or "").strip() or None

    @property
    def running_host(self) -> str:
        return running_hostname(self._hostname)

    # -- identity ----------------------------------------------------------

    def pin(self, *, by: str = "worker") -> InstanceIdentity:
        """Record the identity if this instance has none. Never re-points it."""
        return self.identity.ensure(
            hostname=self.running_host, running_path=self.path, by=by
        )

    def check(self, *, confirm: bool = False) -> IdentityCheck:
        """Whether this process may deliver as the recorded instance."""
        return self.identity.check(
            hostname=self.running_host, running_path=self.path, confirm=confirm
        )

    # -- health ------------------------------------------------------------

    def record_delivery(
        self,
        *,
        status: str,
        at: datetime | None = None,
        alert_id: int | None = None,
        fire_key: str | None = None,
        recipients: int = 0,
        error: str | None = None,
        sender: object | None = None,
    ) -> bool:
        """Record one finished notification. False when the status is not a delivery.

        A status with no health meaning (no sender wired, or nothing to send)
        is not recorded, so the log holds attempts and not ticks.
        """
        outcome = HEALTH_OUTCOME_FOR_STATUS.get(status)
        if outcome is None:
            return False
        self.health.record(
            outcome=outcome,
            at=at,
            alert_id=alert_id,
            fire_key=fire_key,
            recipients=recipients,
            error=error,
            sender=sender,
        )
        return True

    def delivery_health(
        self,
        *,
        now: datetime | None = None,
        window: timedelta = DEFAULT_ALIVE_WINDOW,
    ) -> DeliveryHealth:
        """The read-only "is delivery alive?" answer for this instance."""
        return self.health.read(now=now, window=window)
