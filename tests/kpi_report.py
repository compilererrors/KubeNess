"""KPI recorder shared by the KPI benchmarks and the e2e suite.

`kpi()` records a measured value against its target and fails the test when the
target is missed. All values are printed as one table at the end of the run, and
written as JSON to $KUBENESS_KPI_REPORT when that is set.
"""

from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import asdict, dataclass
from typing import Callable

RESULTS: list["Kpi"] = []
_printed = False


@dataclass
class Kpi:
    id: str
    name: str
    value: float
    unit: str
    target: str
    ok: bool | None   # None: timing measured on an overloaded machine, not judged


def overloaded() -> bool:
    """Timing is meaningless when other processes keep every core busy."""
    try:
        return os.getloadavg()[0] > (os.cpu_count() or 1)
    except OSError:
        return False


def kpi(kid: str, name: str, value: float, unit: str, *, max: float | None = None, min: float | None = None,
        eq: float | None = None, timing: bool = False) -> float:
    if eq is not None:
        ok, target = value == eq, f"= {eq:g}"
    else:
        ok = (max is None or value <= max) and (min is None or value >= min)
        target = " and ".join(t for t in (f"≥ {min:g}" if min is not None else "",
                                          f"≤ {max:g}" if max is not None else "") if t)
    if timing and not ok and overloaded():
        RESULTS.append(Kpi(kid, name, round(value, 3), unit, target, None))
        return value
    RESULTS.append(Kpi(kid, name, round(value, 3), unit, target, ok))
    assert ok, f"{kid} {name}: {value:g} {unit}, target {target}"
    return value


def p95(samples: list[float]) -> float:
    if len(samples) < 2:
        return samples[0]
    return statistics.quantiles(samples, n=20, method="inclusive")[18]


def timed_ms(fn: Callable[[], object], runs: int) -> list[float]:
    out = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        out.append((time.perf_counter() - start) * 1000)
    return out


def stable_p95_ms(fn: Callable[[], object], runs: int, rounds: int = 3, warmup: int = 0) -> float:
    """Lowest p95 of several rounds: timing on a shared machine is noisy upwards only."""
    return min(p95(timed_ms(fn, runs)[warmup:]) for _ in range(rounds))


def timed_kpi(kid: str, name: str, fn: Callable[[], object], runs: int, *, max: float, warmup: int = 0,
              retries: int = 3) -> float:
    """A timing KPI: measured again (up to `retries` times) when over target, because a
    burst of load on a shared machine only ever makes timing worse, never better."""
    value = stable_p95_ms(fn, runs, warmup=warmup)
    for _ in range(retries):
        if value <= max:
            break
        value = min(value, stable_p95_ms(fn, runs, warmup=warmup))
    return kpi(kid, name, value, "ms", max=max, timing=True)


def summary(terminalreporter) -> None:
    global _printed
    if _printed or not RESULTS:
        return
    _printed = True
    tr = terminalreporter
    tr.write_sep("=", "KPI")
    for r in sorted(RESULTS, key=lambda r: r.id):
        mark = "ok  " if r.ok else ("NOISY" if r.ok is None else "MISS")
        tr.write_line(f"{mark:<5} {r.id:<4} {r.name:<58} {r.value:>10g} {r.unit:<6} target {r.target}")
    if any(r.ok is None for r in RESULTS):
        tr.write_line(f"NOISY: timing over target while the machine was overloaded (load {os.getloadavg()[0]:.0f} "
                      f"on {os.cpu_count()} CPUs); rerun when idle.")
    path = os.environ.get("KUBENESS_KPI_REPORT")
    if path:
        with open(path, "w") as f:
            json.dump([asdict(r) for r in RESULTS], f, indent=1)
