"""Run scenarios and probes against both emulators and compare every call."""

from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass, field

import jmespath
from botocore.exceptions import ClientError

from . import judge, smithy
from .services import mws_services
from .diff import Difference, diff_headers, diff_values, make_ignore
from .dsl import Scenario, Step, Unresolved, substitute
from .normalize import Normalizer, jsonable
from .targets import Target


@dataclass(eq=False)
class Case:
    """One compared call: the same request sent to MWS and to LocalStack."""

    id: str
    service: str
    operation: str  # model operation name, e.g. CreateQueue
    method: str  # boto3 method, e.g. create_queue
    kind: str  # scenario | probe:read | probe:validation
    scenario: str = ""
    step: int = 0
    note: str = ""
    params: dict = field(default_factory=dict)  # MWS-side params (after substitution)
    params_localstack: dict = field(default_factory=dict)
    mws: dict = field(default_factory=dict)
    localstack: dict = field(default_factory=dict)
    differences: list[Difference] = field(default_factory=list)
    findings: list[judge.Finding] = field(default_factory=list)
    verdict: judge.Verdict | None = None
    outcome: str = "match"  # match | disparity | spec | skipped | blocked
    skip_reason: str = ""
    expect: dict | None = None


def _materialize(parsed: dict) -> dict:
    """Read streaming bodies so they can be compared and reported."""
    for k, v in list(parsed.items()):
        if hasattr(v, "read") and not isinstance(v, (bytes, str)):
            try:
                parsed[k] = v.read()
            except Exception as e:  # noqa: BLE001
                parsed[k] = f"<stream read failed: {e}>"
    return parsed


def _body_text(body) -> str | None:
    if isinstance(body, (bytes, bytearray)):
        try:
            return bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return None
    return body if isinstance(body, str) else None


CALL_TIMEOUT = 90


def _abort(client) -> None:
    try:
        client._endpoint.http_session.close()  # noqa: SLF001
    except Exception:  # noqa: BLE001
        pass


def invoke(client, method: str, params: dict) -> dict:
    """Call one SDK method and capture everything about the outcome."""
    rec = client._parity_recorder  # noqa: SLF001
    rec.reset()
    started = time.time()
    out: dict = {"status": None, "error": None, "exception": None}
    # A hung emulator must not stall the run: past the deadline, close the
    # client's connections so the pending read fails.
    watchdog = threading.Timer(CALL_TIMEOUT, _abort, args=(client,))
    watchdog.daemon = True
    watchdog.start()
    try:
        resp = getattr(client, method)(**params)
        meta = resp.pop("ResponseMetadata", {})
        out["status"] = meta.get("HTTPStatusCode")
        out["headers"] = meta.get("HTTPHeaders", {})
        out["parsed_obj"] = _materialize(resp)
    except ClientError as e:
        resp = dict(e.response)
        meta = resp.pop("ResponseMetadata", {})
        out["status"] = meta.get("HTTPStatusCode")
        out["headers"] = meta.get("HTTPHeaders", {})
        err = resp.get("Error", {})
        out["error"] = {"code": err.get("Code"), "message": err.get("Message"), "type": err.get("Type")}
        # Extra members of the error shape (e.g. S3's BucketName, KMS's ...).
        extra = {k: v for k, v in err.items() if k not in ("Code", "Message", "Type")}
        rest = {k: v for k, v in resp.items() if k != "Error"}
        out["parsed_obj"] = {"Error": extra, **rest} if extra or rest else {}
    except Exception as e:  # noqa: BLE001 - parse failures are findings, not crashes
        out["exception"] = f"{type(e).__name__}: {e}"
        out["traceback"] = traceback.format_exc(limit=6)
        out["parsed_obj"] = None
    finally:
        watchdog.cancel()
    out["duration_ms"] = round((time.time() - started) * 1000, 1)
    if out["exception"] and out["duration_ms"] >= CALL_TIMEOUT * 1000:
        out["exception"] = f"Timeout: no answer within {CALL_TIMEOUT}s ({out['exception']})"
    out["exchanges"] = [
        {
            "request": {**x.request, "body": jsonable(x.request.get("body"))},
            "response": {**x.response, "body": jsonable(x.response.get("body"))},
        }
        for x in rec.exchanges
    ]
    if rec.exchanges and out["status"] is None and rec.exchanges[-1].response.get("status"):
        out["status"] = rec.exchanges[-1].response["status"]
    raw = rec.exchanges[-1].response.get("body") if rec.exchanges else None
    out["raw_body_text"] = _body_text(raw)
    return out


class ServiceRun:
    """Runs everything for one service with its own clients (one thread)."""

    def __init__(
        self, service, info, mws: Target, ls: Target, run_id: str, health: dict, op_filter=None, log=print, keep_matches=False
    ):
        self.keep_matches = keep_matches
        self.service = service
        self.info = info
        self.targets = {"mws": mws, "localstack": ls}
        self.run_id = run_id
        self.normalizer = Normalizer(run_id)
        self.clients: dict = {}
        self.cases: list[Case] = []
        self.log = log
        self.op_filter = op_filter
        services = health.get("services") if isinstance(health, dict) else None
        self.ls_listed = None if services is None else services
        self.localstack_absent: str | None = None
        self.accounts: dict[str, str] = {}
        self.services_info = mws_services()

    # -- clients ---------------------------------------------------------
    def client(self, side: str, service: str, validate: bool = True):
        key = (side, service, validate)
        if key not in self.clients:
            self.clients[key] = self.targets[side].client(service, validate=validate)
        return self.clients[key]

    def account(self, side: str) -> str:
        if side not in self.accounts:
            try:
                self.accounts[side] = self.client(side, "sts").get_caller_identity()["Account"]
            except Exception:  # noqa: BLE001
                self.accounts[side] = "000000000000"
        return self.accounts[side]

    def model(self, service: str):
        return self.client("mws", service).meta.service_model

    def op_name(self, service: str, method: str) -> str:
        return self.client("mws", service).meta.method_to_api_mapping.get(method, method)

    # -- comparison ------------------------------------------------------
    def compare(self, case: Case, step_ignore: list[str], shape_only: bool, probe: str | None) -> None:
        sm = self.model(case.service)
        try:
            op_model = sm.operation_model(case.operation)
        except Exception:  # noqa: BLE001
            op_model = None
        protocol = sm.metadata.get("protocol", "")
        for side in ("mws", "localstack"):
            r = getattr(case, side)
            obj = r.pop("parsed_obj", None)
            r["raw_parsed"] = jsonable(obj) if obj is not None else None
            r["parsed"] = self.normalizer.value(obj) if obj is not None else None
        m, l_ = case.mws, case.localstack

        if m.get("blocked") or l_.get("blocked"):
            case.outcome = "blocked"
            case.skip_reason = (
                f"needs ${{{m.get('blocked') or l_.get('blocked')}}}, which an earlier step did not produce on "
                + ("MWS" if m.get("blocked") else "LocalStack")
            )
            if m.get("blocked") and l_.get("blocked"):
                case.outcome = "skipped"
            return
        ls_ni = judge.is_not_implemented(l_)
        mws_ni = judge.is_not_implemented(m)
        if ls_ni and mws_ni:
            case.outcome, case.skip_reason = "skipped", "neither side implements this operation"
            return
        if ls_ni:
            case.outcome = "skipped"
            case.skip_reason = f"LocalStack does not offer this ({(l_.get('error') or {}).get('message') or l_.get('status')})"
            return
        if m.get("exception") and l_.get("exception") and probe:
            # Both SDK clients refused to build the request (missing URI labels, ...).
            case.outcome, case.skip_reason = "skipped", f"SDK could not send the request: {m['exception']}"
            return

        diffs: list[Difference] = []
        ignore = make_ignore(step_ignore)
        if m.get("exception") or l_.get("exception"):
            diffs.append(Difference("sdk_exception", "", m.get("exception"), l_.get("exception")))
        if m.get("status") != l_.get("status"):
            diffs.append(Difference("status", "http.status", m.get("status"), l_.get("status")))
        me, le = m.get("error"), l_.get("error")
        if me or le:
            if (me or {}).get("code") != (le or {}).get("code"):
                diffs.append(Difference("error_code", "Error.Code", (me or {}).get("code"), (le or {}).get("code")))
            elif me and le:
                mm = self.normalizer.text(me.get("message") or "")
                lm = self.normalizer.text(le.get("message") or "")
                if mm != lm:
                    diffs.append(Difference("error_message", "Error.Message", me.get("message"), le.get("message")))
        if not (me or le) and not (m.get("exception") or l_.get("exception")):
            diff_values(m.get("parsed"), l_.get("parsed"), "", diffs, shape_only, ignore)
        elif me and le and not shape_only:
            # Extra members of the error body (S3's BucketName, `message`, ...).
            extra: list[Difference] = []
            diff_values(m.get("parsed") or {}, l_.get("parsed") or {}, "", extra, True, ignore)
            for d in extra:
                d.note = f"error body: {d.kind}" + (f", {d.note}" if d.note else "")
                d.kind = "error_body"
            diffs += extra
        if not (m.get("exception") or l_.get("exception")):
            diff_headers(m.get("headers"), l_.get("headers"), diffs)
        case.differences = diffs

        findings: list[judge.Finding] = []
        declared = None
        info = self.services_info.get(case.service)
        if info is not None:
            declared = smithy.declared_errors(info.model, case.operation)
        for side, r in (("mws", m), ("localstack", l_)):
            findings += judge.model_findings(side, r, op_model, protocol, probe, declared)
            findings += judge.expectation_findings(side, r, case.expect)
        case.findings = findings
        substantive = [d for d in diffs if d.severity != "minor"]
        if diffs:
            case.outcome = "disparity" if substantive or any(f.side == "mws" for f in findings) else "minor"
            case.verdict = judge.verdict(diffs, findings, m, l_, probe)
        elif any(f.side == "mws" and f.confidence != "low" for f in findings):
            case.outcome = "spec"
            case.verdict = judge.verdict(diffs, [f for f in findings if f.side == "mws"], m, l_, probe)
        else:
            case.outcome = "match"
        if case.outcome in ("match", "skipped") and not self.keep_matches:
            # Keep memory bounded: matching calls need no debug detail.
            for side in ("mws", "localstack"):
                r = getattr(case, side)
                setattr(case, side, {k: r.get(k) for k in ("status", "error", "duration_ms")})

    # -- scenarios -------------------------------------------------------
    def builtin_vars(self, side: str, sc_index: int) -> dict:
        name = f"pty-{self.run_id}-{sc_index}"
        return {
            "name": name,
            "alnum": name.replace("-", ""),
            "run": self.run_id,
            "account": self.account(side),
            "region": self.targets[side].region,
            "endpoint": self.targets[side].endpoint,
        }

    def run_step(self, side: str, step: Step, variables: dict) -> tuple[dict, dict]:
        try:
            params = step.params(variables) if callable(step.params) else substitute(step.params, variables)
        except Unresolved as u:
            return {}, {"blocked": u.name, "status": None, "error": None, "exception": None, "parsed_obj": None}
        except KeyError as k:
            return {}, {"blocked": str(k), "status": None, "error": None, "exception": None, "parsed_obj": None}
        client = self.client(side, step.service, validate=not step.raw)
        deadline = time.time() + step.wait_seconds
        while True:
            result = invoke(client, step.op, params)
            if step.until is None or time.time() > deadline:
                break
            obj = result.get("parsed_obj")
            try:
                # Errors are retried too (eventual consistency), until the deadline.
                done = not result.get("error") and not result.get("exception") and (
                    step.until(obj) if callable(step.until) else bool(jmespath.search(step.until, obj or {}))
                )
            except Exception:  # noqa: BLE001
                done = False
            if done:
                break
            time.sleep(1)
        obj = result.get("parsed_obj")
        if obj is not None and not result.get("error"):
            for var, expr in step.save.items():
                try:
                    val = expr(obj) if callable(expr) else jmespath.search(expr, obj)
                except Exception:  # noqa: BLE001
                    val = None
                if val is not None:
                    variables[var] = val
        return params, result

    def run_scenario(self, sc: Scenario, index: int) -> None:
        variables = {side: self.builtin_vars(side, index) for side in self.targets}
        for i, step in enumerate(sc.steps, 1):
            if self.localstack_absent and not step.cleanup:
                continue
            method = step.op
            op = self.op_name(step.service, method)
            case = Case(
                id=f"{sc.service}/{sc.slug}/{i:02d}-{method}",
                service=step.service,
                operation=op,
                method=method,
                kind="scenario",
                scenario=sc.title,
                step=i,
                note=step.note,
                expect=step.expect,
            )
            if self.op_filter and not self.op_filter(case):
                # Still run the call so later steps get their variables.
                for side in self.targets:
                    self.run_step(side, step, variables[side])
                continue
            pm, case.mws = self.run_step("mws", step, variables["mws"])
            pl, case.localstack = self.run_step("localstack", step, variables["localstack"])
            case.params, case.params_localstack = jsonable(pm), jsonable(pl)
            self.compare(case, step.ignore, step.shape_only, None)
            self.cases.append(case)
            if (
                i == 1
                and case.outcome == "skipped"
                and judge.is_not_implemented(case.localstack)
                and self.ls_listed is not None
                and step.service == self.service
            ):
                self.localstack_absent = case.skip_reason

    # -- probes ----------------------------------------------------------
    def probe_ops(self, kinds: set[str]):
        sm = self.model(self.service)
        mapping = {v: k for k, v in self.client("mws", self.service).meta.method_to_api_mapping.items()}
        for op in sm.operation_names:
            om = sm.operation_model(op)
            if om.has_event_stream_output or om.has_event_stream_input or getattr(om, "deprecated", False):
                continue
            inp = om.input_shape
            required = list(inp.required_members) if inp is not None else []
            if not required and "read" in kinds and op.startswith(("List", "Describe", "Get")):
                yield "read", op, mapping.get(op)
            elif required and "validation" in kinds:
                yield "validation", op, mapping.get(op)

    def run_probes(self, kinds: set[str]) -> None:
        for kind, op, method in self.probe_ops(kinds):
            if method is None:
                continue
            case = Case(
                id=f"{self.service}/probe-{kind}/{method}",
                service=self.service,
                operation=op,
                method=method,
                kind=f"probe:{kind}",
                note=(
                    "read-only call without arguments; emulator state differs, so only the response shape is compared"
                    if kind == "read"
                    else "every required member omitted (client-side validation off); AWS must reject it"
                ),
            )
            if self.op_filter and not self.op_filter(case):
                continue
            validate = kind == "read"
            case.mws = invoke(self.client("mws", self.service, validate), method, {})
            case.localstack = invoke(self.client("localstack", self.service, validate), method, {})
            self.compare(case, [], kind == "read", kind)
            self.cases.append(case)

    def check_localstack_offers(self) -> None:
        """Skip the whole service quickly when LocalStack lacks it."""
        from .services import localstack_name

        if self.ls_listed is None:
            return
        name = localstack_name(self.service)
        if name in self.ls_listed and self.ls_listed[name] != "disabled":
            return
        # Not listed: confirm with one cheap call (names in health differ for a few services).
        ops = sorted((k != "read", op, m) for k, op, m in self.probe_ops({"read", "validation"}) if m)
        for validation, op, method in ops[:1]:
            r = invoke(self.client("localstack", self.service, not validation), method, {})
            if judge.is_not_implemented(r):
                err = r.get("error") or {}
                self.localstack_absent = (
                    f"not listed in LocalStack's /_localstack/health, and LocalStack answers {op} with "
                    f"HTTP {r.get('status')} {err.get('code')}: {err.get('message') or ''}"
                ).strip()
