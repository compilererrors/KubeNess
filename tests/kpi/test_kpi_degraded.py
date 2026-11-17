"""KPI benchmarks for B14 (observer degraded)."""

from __future__ import annotations

from kpi_report import kpi
from test_degraded import BUDGET, Lab

INTERVAL = 10


def test_d01_d02_degraded_detection_and_recovery():
    lab = Lab()
    for t in range(0, 100, INTERVAL):
        lab.tick(t, ok=True)
    last_success = 90
    for t in range(100, 600, INTERVAL):
        lab.tick(t, ok=False)
    fired = lab.first("observerDegraded", "fired")
    kpi("D01", "stale to observerDegraded firing", fired - last_success, "s",
        max=BUDGET.total_seconds() + INTERVAL)
    for t in range(600, 1200, INTERVAL):
        lab.tick(t, ok=True)
    resolved = [1 for _, r, k in lab.transitions if r == "observerDegraded" and k == "resolved"]
    kpi("D02", "resolved transitions after recovery", len(resolved), "count", eq=1)


def test_d03_transient_errors_are_not_incidents():
    lab = Lab()
    for t in range(0, 100, INTERVAL):
        lab.tick(t, ok=True)
    for t in range(100, 220, INTERVAL):      # two minutes of errors, budget is three
        lab.tick(t, ok=False)
    for t in range(220, 600, INTERVAL):
        lab.tick(t, ok=True)
    kpi("D03", "incidents from errors shorter than the budget", len(lab.store.list_incidents()), "count", eq=0)
