"""B21: the model comparison harness, exercised with fake models."""

from __future__ import annotations

import json

from kubeness.compare import FIXTURES, compare, render

from test_diagnose import FakeModel


class Scripted(FakeModel):
    """Replies per fixture: cites the first fact's evidence and names a keyword."""

    def __init__(self, good=True, bad_json=False):
        super().__init__()
        self.good, self.bad_json = good, bad_json

    def chat(self, messages, schema, timeout):
        self.calls.append(messages)
        if self.bad_json:
            return "not json"
        data = json.loads(messages[1]["content"])
        ref = data["facts"][0]["evidence"][0]
        return json.dumps({
            "summary": "s",
            "possible_causes": [{"text": "c", "evidence_refs": [ref] if self.good else ["e99"]}],
            "next_checks": ["Check the config, image tag, probe, logs and memory limit."] if self.good else ["Look."],
        })


def test_fixtures_cover_the_planned_cases():
    names = [f.name for f in FIXTURES]
    assert len(names) == 6 and {"crash-config", "image-tag", "readiness-probe", "logs-missing", "oom", "ambiguous"} <= set(names)


def test_compare_reports_template_and_models():
    rows = compare({"good": Scripted(), "bad": Scripted(good=False), "broken": Scripted(bad_json=True)})
    by = {r.model: r for r in rows}
    assert set(by) == {"template", "good", "bad", "broken"}
    assert by["template"].unsupported == 0 and by["template"].schema_errors == 0
    assert by["good"].unsupported == 0 and by["good"].useful_checks == 6
    assert by["bad"].unsupported == 6 and by["bad"].useful_checks == 0
    assert by["broken"].schema_errors == 6
    assert by["template"].useful_checks >= 4, "the runbooks name the object in most fixtures"
    text = render(rows)
    assert "| template |" in text and "| good |" in text and "p95" in text


# --- strategies: tiered vs. one model, and troubleshooting ---------------------------------------

class Vague(Scripted):
    def chat(self, messages, schema, timeout):
        out = json.loads(super().chat(messages, schema, timeout))
        out["next_checks"] = ["Look at the system."]
        return json.dumps(out)


def test_strategies_combine_runs_and_count_escalations():
    from kubeness.compare import strategies
    rows = {r.name: r for r in strategies({"small": Vague(), "big": Scripted()}, small="small", big=["big"])}
    assert set(rows) == {"only small", "only big", "small → big (invalid+ungrounded)",
                         "small → big (invalid+unsupported)"}
    assert rows["small → big (invalid+unsupported)"].escalations == 0, "vague but supported answers stay small"
    tiered = rows["small → big (invalid+ungrounded)"]
    assert tiered.escalations == 6 and tiered.useful_checks == 6
    assert rows["only small"].escalations == 0 and rows["only small"].useful_checks == 0
    assert tiered.latency_ms == [a + b for a, b in zip(rows["only small"].latency_ms, rows["only big"].latency_ms)]


class Investigator:
    """Uses one tool, then concludes from what it saw."""

    def __init__(self, tool_first=True):
        self.tool_first, self.last_thinking = tool_first, ""

    def chat(self, messages, schema, timeout):
        data = json.loads(messages[1]["content"])
        prev = data["previous_steps"]
        if self.tool_first and not prev:
            return json.dumps({"tool": "logs" if "crash" in data["incident"] else "rolloutHistory",
                               "args": {"pod": data["pods"][0], "container": "app", "previous": True}})
        ref = prev[-1]["evidence_id"] if prev else "e1"
        fix = {"action": "rollback-deployment", "reason": "revision 1 worked", "evidence_refs": [ref]} \
            if "image" in data["incident"] else None
        return json.dumps({"tool": "finish", "args": {
            "summary": "s", "findings": [{"text": "The config file is missing; the image tag does not exist.",
                                          "evidence_refs": [ref]}], **({"fix": fix} if fix else {})}})


def test_troubleshooting_benchmark_scores_tool_use_cause_and_fix():
    from kubeness.compare import TROUBLE, troubleshoot_bench
    assert [s.name for s in TROUBLE] == ["crash-config", "image-tag"]
    rows = {r.model: r for r in troubleshoot_bench({"careful": Investigator(), "hasty": Investigator(False)})}
    assert rows["careful"].used_tools == 2 and rows["careful"].causes_found == 2 and rows["careful"].right_fix == 2
    assert rows["hasty"].used_tools == 0 and rows["hasty"].right_fix == 1, "no fix without investigating"
