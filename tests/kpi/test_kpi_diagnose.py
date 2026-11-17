"""KPI benchmarks for stage 2 (Diagnose)."""

from __future__ import annotations


from kubeness.analysis import Claim
from kubeness.model import encode_input, model_input
from kubeness.redact import redact

from kpi_report import kpi, timed_kpi
from test_diagnose import FakeLogs, FakeModel, model_reply, run_crash_loop

SECRETS = [
    ("password=hunter2 user=bob", "hunter2"),
    ('{"api_key": "abc123def"}', "abc123def"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "eyJhbGci"),
    ("Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l", "YWxhZGRpbjpvcGVuc2VzYW1l"),
    ("aws AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("session ASIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"),
    ("connecting to postgres://app:s3cr3t@db:5432/app", "s3cr3t"),
    ("DB_PASSWORD: 'x9!y'", "x9!y"),
    ("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghij"),
    ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890"),
    ("api key sk-abcdefghijklmnopqrstuvwx", "sk-abcdefghijklmnop"),
    ("client_secret = 'Zm9vYmFy'", "Zm9vYmFy"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
    ("redis://:supersecret@cache:6379", "supersecret"),
]

ORDINARY = [
    "GET /api/users 200 12ms",
    "connection refused to db:5432, retrying in 5s (attempt=3)",
    "fatal: config file /etc/app/config.yaml not found",
    "key not found in cache: user:42",
    "listening on 0.0.0.0:8080",
    "panic: runtime error: index out of range [3] with length 3",
    "Started container app image=ghcr.io/example/web:1.0",
    "token bucket refilled, 100 tokens available",
    "OOM: memory limit 256Mi exceeded",
]


def test_k10_secret_corpus_is_masked():
    masked = sum(1 for text, leak in SECRETS if leak not in redact(text)[0])
    kpi("K10", "secret corpus masked", 100 * masked / len(SECRETS), "%", eq=100)


def test_k11_ordinary_text_is_kept():
    false = sum(1 for text in ORDINARY if redact(text)[1])
    kpi("K11", "false masks in ordinary log lines", false, "count", eq=0)


def test_k12_redaction_speed():
    # Worst realistic case: every pattern's hint occurs, so every pattern runs.
    lines = ["2026-11-16T10:00:00Z INFO request handled path=/api/v1/items status=200 took=12ms"] * 19
    lines.append("2026-11-16T10:00:01Z WARN auth token=abc123 user=bob url=https://u:p@host/ Bearer xyz12345678")
    text = ("\n".join(lines) + "\n") * 9
    text = text[:16384]
    timed_kpi("K12", "redaction time p95, 16 KiB log", lambda: redact(text), 30, max=5)


def test_k13_log_evidence_is_bounded():
    big = "".join(f"line {i:05d} " + "x" * 90 + "\n" for i in range(1000))
    _, store, _, inc = run_crash_loop(logs=FakeLogs(text=big))
    log = next(e for e in store.evidence(inc.id) if e.kind == "log")
    kpi("K13", "log evidence size", len(log.payload["text"].encode()) / 1024, "KiB", max=16)
    kpi("K13", "log evidence lines", log.payload["text"].count("\n"), "lines", max=100)
    assert log.payload["truncated"]


def test_k14_no_unsupported_claims_stored():
    def reply(refs):
        r = model_reply(refs)
        r["possible_causes"].append({"text": "invented", "evidence_refs": ["e99"]})
        return r

    model = FakeModel(reply=reply(["e1"]))
    _, store, analyzer, inc = run_crash_loop(logs=FakeLogs(), model=model)
    analyzer.run_model(inc.id)
    refs = {e.ref for e in store.evidence(inc.id)}
    bad = 0
    for rec in store.analyses(inc.id):
        if rec.payload:
            for c in rec.payload["observed_facts"] + rec.payload["possible_causes"]:
                bad += not c["evidence_refs"] or not set(c["evidence_refs"]) <= refs
    kpi("K14", "stored claims without a valid evidence ref", bad, "count", eq=0)


def test_k15_model_input_is_bounded():
    big = "".join(f"fatal: {'y' * 500}\n" for _ in range(200))
    _, store, analyzer, inc = run_crash_loop(logs=FakeLogs(text=big))
    from kubeness.analysis import Analysis
    tmpl = Analysis.model_validate(store.analyses(inc.id)[0].payload)
    tmpl.observed_facts = [Claim(text="z" * 500, evidence_refs=["e1"]) for _ in range(10)]
    tmpl.missing_information = ["m" * 500 for _ in range(6)]
    size = len(encode_input(model_input(inc, tmpl)))
    kpi("K15", "model input size", size / 1024, "KiB", max=4)
