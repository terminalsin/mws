"""Write the parity report: report.json (everything), report.md (an index
and work list), and one JSON + Markdown file per disparity under cases/.

Each case file stands on its own: the operation, the exact arguments, the
full raw HTTP exchange on both sides, both parsed responses, the normalized
diff, the model checks and the verdict, plus where the MWS code and model
live and the command that reruns just that case.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from .diff import SEVERITY_RANK

MD_BODY_LIMIT = 20_000

OUTCOME_ORDER = ["disparity", "spec", "minor", "blocked", "match", "skipped"]
OUTCOME_HELP = {
    "disparity": "the two sides answered differently (status, error code, fields or values)",
    "spec": "both sides agree, but MWS departs from the AWS service model",
    "minor": "only wording, header or empty-vs-absent differences",
    "blocked": "an earlier step failed on one side, so this call could not be made there",
    "match": "identical after normalization",
    "skipped": "LocalStack does not offer it (or neither side does)",
}


def safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def case_dict(case, full: bool = True) -> dict:
    d = {
        "id": case.id,
        "service": case.service,
        "operation": case.operation,
        "boto3_method": case.method,
        "kind": case.kind,
        "scenario": case.scenario,
        "step": case.step,
        "outcome": case.outcome,
        "skip_reason": case.skip_reason,
        "note": case.note,
        "severity": worst_severity(case),
        "verdict": case.verdict.to_dict() if case.verdict else None,
    }
    if not full:
        d["status"] = {"mws": case.mws.get("status"), "localstack": case.localstack.get("status")}
        return d
    d.update(
        {
            "expected_aws_behaviour": case.expect,
            "params": case.params,
            "params_localstack": case.params_localstack if case.params_localstack != case.params else "<same>",
            "differences": [x.to_dict() for x in case.differences],
            "findings": [f.to_dict() for f in case.findings],
            "mws": side_dict(case.mws),
            "localstack": side_dict(case.localstack),
        }
    )
    return d


def side_dict(r: dict) -> dict:
    keep = ["status", "error", "exception", "traceback", "blocked", "duration_ms", "headers", "parsed", "raw_parsed", "exchanges"]
    return {k: r.get(k) for k in keep if k in r}


def worst_severity(case) -> str | None:
    if not case.differences:
        return None
    return min((d.severity for d in case.differences), key=lambda s: SEVERITY_RANK[s])


def rerun_command(case) -> str:
    return f"python -m parity --services {case.service} --case '{case.id}'"


def _json(v) -> str:
    return json.dumps(v, indent=2, sort_keys=True, default=str)


def _clip(s: str) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= MD_BODY_LIMIT else s[:MD_BODY_LIMIT] + f"\n... <{len(s) - MD_BODY_LIMIT} more chars in the .json file>"


def _http(ex: dict) -> str:
    req, resp = ex.get("request", {}), ex.get("response", {})
    lines = [f"{req.get('method', '?')} {req.get('url', '?')}"]
    lines += [f"{k}: {v}" for k, v in (req.get("headers") or {}).items()]
    body = req.get("body")
    lines += ["", body if isinstance(body, str) else _json(body)] if body not in (None, "", b"") else []
    lines += ["", "--- response ---"]
    if "exception" in resp:
        lines.append(resp["exception"])
    else:
        lines.append(f"HTTP {resp.get('status')}")
        lines += [f"{k}: {v}" for k, v in (resp.get("headers") or {}).items()]
        rb = resp.get("body")
        lines += ["", rb if isinstance(rb, str) else _json(rb)]
    return _clip("\n".join(lines))


def case_markdown(case, services: dict) -> str:
    info = services.get(case.service)
    v = case.verdict
    out = [f"# {case.id}", ""]
    out.append(f"- **Service / operation:** `{case.service}` / `{case.operation}` (boto3 `{case.method}`)")
    out.append(f"- **Kind:** {case.kind}" + (f", scenario *{case.scenario}* step {case.step}" if case.scenario else ""))
    out.append(f"- **Outcome:** {case.outcome} ({OUTCOME_HELP.get(case.outcome, '')})")
    if case.skip_reason:
        out.append(f"- **Why:** {case.skip_reason}")
    if v:
        out.append(f"- **Likely wrong:** **{v.likely_wrong}** (confidence {v.confidence})")
    if info:
        out.append(f"- **MWS code:** `{info.crate}` (model `{info.model}`)")
    out.append(f"- **Rerun:** `{rerun_command(case)}`")
    if case.note:
        out.append(f"- **Note:** {case.note}")
    out.append("")
    if v and v.reasons:
        out += ["## Verdict reasons", ""] + [f"- {r}" for r in v.reasons] + [""]
    if case.expect:
        out += ["## Documented AWS behaviour", "", "```json", _json(case.expect), "```", ""]
    if case.differences:
        out += ["## Differences (after normalization)", "", "| severity | kind | path | MWS | LocalStack | note |", "| --- | --- | --- | --- | --- | --- |"]
        for d in sorted(case.differences, key=lambda d: SEVERITY_RANK[d.severity]):
            cell = lambda x: "`" + json.dumps(x, default=str)[:300].replace("|", "\\|") + "`"  # noqa: E731
            out.append(f"| {d.severity} | {d.kind} | `{d.path}` | {cell(d.mws)} | {cell(d.localstack)} | {d.note} |")
        out.append("")
    if case.findings:
        out += ["## Model checks", ""] + [f"- **{f.side}** `{f.check}` ({f.confidence}): {f.detail}" for f in case.findings] + [""]
    out += ["## Request parameters", "", "```json", _clip(_json(case.params)), "```", ""]
    if case.params_localstack and case.params_localstack != case.params:
        out += ["LocalStack-side parameters (variables differ per side):", "", "```json", _clip(_json(case.params_localstack)), "```", ""]
    for label, r in (("MWS", case.mws), ("LocalStack", case.localstack)):
        out += [f"## {label}", ""]
        if r.get("blocked"):
            out += [f"Not called: variable `${{{r['blocked']}}}` was not produced by an earlier step.", ""]
            continue
        out.append(f"- status: {r.get('status')}, time: {r.get('duration_ms')} ms")
        if r.get("error"):
            out.append(f"- error: `{r['error'].get('code')}`: {r['error'].get('message')}")
        if r.get("exception"):
            out += [f"- SDK exception: `{r['exception']}`", "", "```", r.get("traceback", ""), "```"]
        out += ["", "Parsed response (normalized):", "", "```json", _clip(_json(r.get("parsed"))), "```", ""]
        out += ["Parsed response (raw):", "", "```json", _clip(_json(r.get("raw_parsed"))), "```", ""]
        for i, ex in enumerate(r.get("exchanges") or [], 1):
            out += [f"Raw HTTP exchange {i}:", "", "```http", _http(ex), "```", ""]
    return "\n".join(out)


def write(out_dir: Path, meta: dict, cases: list, services: dict, service_status: dict, keep_matches: bool) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    interesting = [c for c in cases if c.outcome in ("disparity", "spec", "minor", "blocked")]
    full_ids = {id(c) for c in interesting}
    by_service: dict[str, Counter] = defaultdict(Counter)
    for c in cases:
        by_service[c.service][c.outcome] += 1

    for c in interesting:
        base = cases_dir / safe(c.service) / safe(c.id.split("/", 1)[1])
        base.parent.mkdir(parents=True, exist_ok=True)
        base.with_suffix(".json").write_text(_json(case_dict(c)))
        base.with_suffix(".md").write_text(case_markdown(c, services))
        c.report_path = base.relative_to(out_dir).as_posix()

    summary = {
        "outcomes": dict(Counter(c.outcome for c in cases)),
        "likely_wrong": dict(Counter(c.verdict.likely_wrong for c in interesting if c.verdict)),
        "per_service": {s: dict(v) for s, v in sorted(by_service.items())},
    }
    report = {
        "meta": meta,
        "summary": summary,
        "outcome_meanings": OUTCOME_HELP,
        "services": {
            s: {**service_status.get(s, {}), **(services[s].__dict__ if s in services else {})}
            for s in sorted(set(service_status) | set(by_service))
        },
        "cases": [
            {**case_dict(c, full=id(c) in full_ids or keep_matches), "report_path": getattr(c, "report_path", None)}
            for c in cases
        ],
    }
    (out_dir / "report.json").write_text(_json(report))
    (out_dir / "report.md").write_text(index_markdown(meta, cases, interesting, services, service_status, by_service))
    return out_dir


def index_markdown(meta, cases, interesting, services, service_status, by_service) -> str:
    out = [
        "# MWS vs LocalStack parity report",
        "",
        f"- Run `{meta['run_id']}`, {meta['started']} to {meta['finished']}",
        f"- MWS: {meta['mws']['endpoint']}",
        f"- LocalStack: {meta['localstack']['endpoint']} ({meta['localstack'].get('edition', '?')} {meta['localstack'].get('version', '')})",
        f"- Command: `{meta['command']}`",
        "",
        "LocalStack is a reference, not ground truth. MWS follows real AWS, so each",
        "disparity carries a verdict built from documented AWS behaviour and the",
        "official service model (see tests/parity/README.md). Each case file under",
        "`cases/` has the full raw HTTP of both sides and the command to rerun it.",
        "",
        "| outcome | meaning | count |",
        "| --- | --- | --- |",
    ]
    counts = Counter(c.outcome for c in cases)
    for o in OUTCOME_ORDER:
        out.append(f"| {o} | {OUTCOME_HELP[o]} | {counts.get(o, 0)} |")
    out += ["", "## Services", "", "| service | MWS crate | compared | disparity | spec | minor | blocked | match | skipped | note |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for s in sorted(set(service_status) | set(by_service)):
        c = by_service.get(s, Counter())
        st = service_status.get(s, {})
        crate = services[s].crate if s in services else ""
        total = sum(c.values()) - c.get("skipped", 0)
        out.append(
            f"| {s} | `{crate}` | {total} | {c.get('disparity', 0)} | {c.get('spec', 0)} | {c.get('minor', 0)} | "
            f"{c.get('blocked', 0)} | {c.get('match', 0)} | {c.get('skipped', 0)} | {st.get('reason', '')} |"
        )

    def row(c):
        v = c.verdict
        first = sorted(c.differences, key=lambda d: SEVERITY_RANK[d.severity])[:2]
        what = "; ".join(f"{d.kind} `{d.path}`: {json.dumps(d.mws, default=str)[:80]} vs {json.dumps(d.localstack, default=str)[:80]}" for d in first)
        if not what and c.findings:
            what = c.findings[0].detail[:160]
        if c.outcome == "blocked":
            what = c.skip_reason
        conf = f"{v.likely_wrong} ({v.confidence})" if v else "-"
        return f"| [{c.id}]({c.report_path}.md) | {c.outcome} | {worst_severity(c) or '-'} | {conf} | {what.replace('|', '/')} |"

    def section(title, items, blurb):
        nonlocal out
        if not items:
            return
        out += ["", f"## {title} ({len(items)})", "", blurb, "", "| case | outcome | severity | likely wrong | first differences |", "| --- | --- | --- | --- | --- |"]
        key = lambda c: (c.service, SEVERITY_RANK.get(worst_severity(c) or "minor", 3), c.id)  # noqa: E731
        out += [row(c) for c in sorted(items, key=key)]

    mws_wrong = [c for c in interesting if c.verdict and c.verdict.likely_wrong in ("mws", "both")]
    ls_wrong = [c for c in interesting if c.verdict and c.verdict.likely_wrong == "localstack"]
    unknown = [c for c in interesting if c.outcome != "blocked" and (not c.verdict or c.verdict.likely_wrong == "undetermined")]
    blocked = [c for c in interesting if c.outcome == "blocked"]
    section("MWS likely wrong: fix these first", mws_wrong, "Evidence points at MWS (model checks, documented AWS answers, 5xx or not-implemented answers).")
    section("Undetermined: check against AWS documentation", unknown, "No model evidence either way. Real AWS decides; when MWS is right, consider adding an `expect` to the scenario.")
    section("LocalStack likely wrong", ls_wrong, "Evidence points at LocalStack. Usually nothing to fix in MWS; listed so the call is visible.")
    section("Blocked steps", blocked, "An earlier step failed on one side; fix that one first.")
    skipped = [s for s, st in service_status.items() if st.get("status") == "skipped"]
    if skipped:
        out += ["", "## Services skipped", ""] + [f"- **{s}**: {service_status[s].get('reason')}" for s in sorted(skipped)]
    return "\n".join(out) + "\n"
