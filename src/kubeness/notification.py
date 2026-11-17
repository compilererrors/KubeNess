"""The fixed notification format shared by observer and notifier.

The notifier accepts only these fields. Destination, provider and credentials
come from the notifier's own configuration, never from the payload.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Event = Literal["firing", "reopened", "repeat", "escalated", "resolved", "digest"]
Severity = Literal["info", "warning", "critical"]

MAX_TEXT = 1500


class NotificationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str = Field(max_length=120, pattern=r"^[A-Za-z0-9:._-]+$")
    event: Event
    severity: Severity
    incident: str = Field(max_length=64)
    cluster: str = Field(max_length=63)
    namespace: str = Field(max_length=63)
    workload: str = Field(max_length=320)
    rule: str = Field(max_length=32)
    state: Literal["firing", "recovering", "resolved", "info"]
    observed: str = Field(max_length=500)
    possible_cause: str = Field("", max_length=300, alias="possibleCause")
    next_check: str = Field("", max_length=300, alias="nextCheck")
    missing: list[str] = Field(default_factory=list, max_length=2)
    first_seen: datetime = Field(alias="firstSeen")
    last_observed: datetime = Field(alias="lastObserved")
    recurrence: int = Field(0, ge=0)
    # Digest only: one line per info event.
    items: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=20)
    text: str = Field(max_length=MAX_TEXT)

    def wire(self) -> dict:
        return self.model_dump(mode="json", by_alias=True)


TITLES = {
    "firing": "Firing",
    "reopened": "Firing again",
    "repeat": "Still firing",
    "escalated": "Escalated",
    "resolved": "Resolved",
    "digest": "Digest",
}


def title(p: NotificationPayload) -> str:
    if p.event == "digest":
        return f"[INFO] Digest: {len(p.items)} event{'s' if len(p.items) != 1 else ''} in {p.namespace}"
    tag = "RESOLVED" if p.event == "resolved" else p.severity.upper()
    return f"[{tag}] {TITLES[p.event]}: {p.workload} in {p.namespace}"


def render_text(p: NotificationPayload) -> str:
    """Plain text for e-mail and push. Built from the deterministic fields only."""
    if p.event == "digest":
        lines = [title(p), p.observed, *[f"- {i}" for i in p.items], f"Cluster {p.cluster}."]
        text = "\n".join(lines)
        return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"
    lines = [title(p), f"Rule {p.rule}: {p.observed}"]
    if p.event != "resolved":
        if p.possible_cause:
            lines.append(f"Possible cause (hypothesis): {p.possible_cause}")
        if p.next_check:
            lines.append(f"Next check: {p.next_check}")
        if p.missing:
            lines.append("Missing: " + "; ".join(p.missing))
    if p.recurrence:
        lines.append(f"Recurrence {p.recurrence} within the reopen window.")
    lines.append(f"First seen {p.first_seen:%Y-%m-%d %H:%M:%S}Z, last observed {p.last_observed:%Y-%m-%d %H:%M:%S}Z.")
    lines.append(f"Cluster {p.cluster}, incident {p.incident}.")
    text = "\n".join(lines)
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"
