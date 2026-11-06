"""Command line: `python -m parity --help` (run from tests/parity)."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import os
import secrets
import shlex
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import report, scenarios  # noqa: F401 - scenarios register themselves
from .dsl import REGISTRY
from .runner import Case, ServiceRun
from .services import mws_services
from .targets import (
    MWS_ROOT_KEY,
    MWS_ROOT_SECRET,
    Launched,
    Target,
    localstack_health,
    localstack_info,
    mws_health,
    start_localstack,
    start_mws,
)

HERE = Path(__file__).resolve().parent.parent


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="python -m parity",
        description="Send identical boto3 calls to MWS and LocalStack and report every difference.",
    )
    p.add_argument("--mws", default=os.environ.get("PARITY_MWS_ENDPOINT", "http://localhost:4567"), help="MWS endpoint (default %(default)s)")
    p.add_argument(
        "--localstack",
        default=os.environ.get("PARITY_LOCALSTACK_ENDPOINT", "http://localhost:4566"),
        help="LocalStack endpoint (default %(default)s)",
    )
    p.add_argument("--start-mws", action="store_true", help="start MWS (target/debug/mws, $MWS_BIN or cargo run) on the --mws port")
    p.add_argument("--mws-bin", help="MWS binary for --start-mws")
    p.add_argument("--start-localstack", action="store_true", help="start LocalStack in Docker on the --localstack port")
    p.add_argument("--localstack-image", default=os.environ.get("PARITY_LOCALSTACK_IMAGE", "localstack/localstack:latest"))
    p.add_argument("--mws-key", default=os.environ.get("PARITY_MWS_ACCESS_KEY_ID", MWS_ROOT_KEY))
    p.add_argument("--mws-secret", default=os.environ.get("PARITY_MWS_SECRET_ACCESS_KEY", MWS_ROOT_SECRET))
    p.add_argument("--localstack-key", default=os.environ.get("PARITY_LOCALSTACK_ACCESS_KEY_ID", "test"))
    p.add_argument("--localstack-secret", default=os.environ.get("PARITY_LOCALSTACK_SECRET_ACCESS_KEY", "test"))
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--services", help="comma-separated boto3 service names (default: every MWS service)")
    p.add_argument("--exclude", default="", help="comma-separated services to leave out")
    p.add_argument(
        "--mode",
        default="all",
        choices=["all", "scenarios", "probes", "read", "validation"],
        help="scenarios = hand-written call sequences; probes = read + validation probes of every operation",
    )
    p.add_argument("--case", action="append", default=[], help="only cases whose id matches this glob (repeatable)")
    p.add_argument("--operation", action="append", default=[], help="only these model operations, e.g. CreateQueue (repeatable)")
    p.add_argument("--out", help="report directory (default tests/parity/reports/<timestamp>)")
    p.add_argument("--jobs", type=int, default=4, help="services compared in parallel (default %(default)s)")
    p.add_argument("--keep-matches", action="store_true", help="also write full details of matching calls to report.json")
    p.add_argument("--list", action="store_true", help="list services and scenarios, then exit")
    p.add_argument(
        "--self-test",
        action="store_true",
        help="the reference endpoint is a second MWS (MWS credentials, no LocalStack health check): "
        "checks that the suite itself reports no differences between two identical emulators",
    )
    p.add_argument("--fail-on", choices=["never", "disparity", "mws"], default="never", help="exit 1 on any disparity, or only when MWS is likely wrong")
    return p.parse_args(argv)


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    args = parse_args(argv)
    args.argv = argv
    services = mws_services()
    wanted = [s.strip() for s in args.services.split(",")] if args.services else sorted(services)
    excluded = {s.strip() for s in args.exclude.split(",") if s.strip()}
    unknown = [s for s in wanted if s not in services]
    if unknown:
        print(f"unknown services {unknown}; MWS implements: {', '.join(sorted(services))}", file=sys.stderr)
        return 2
    wanted = [s for s in wanted if s not in excluded]
    by_service: dict[str, list] = {}
    for sc in REGISTRY:
        by_service.setdefault(sc.service, []).append(sc)
    if args.list:
        for s in wanted:
            titles = [sc.title for sc in by_service.get(s, [])]
            print(f"{s:28} {services[s].crate:40} {len(titles)} scenarios: {'; '.join(titles)}")
        return 0

    run_id = secrets.token_hex(3)
    started = dt.datetime.now(dt.timezone.utc)
    out_dir = Path(args.out) if args.out else HERE / "reports" / started.strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    launched = Launched()
    try:
        if args.start_mws:
            args.mws = start_mws(_port(args.mws), launched, args.mws_bin, out_dir / "mws.log")
        if args.start_localstack:
            args.localstack = start_localstack(_port(args.localstack), launched, args.localstack_image)
        return run(args, wanted, by_service, services, run_id, started, out_dir)
    finally:
        launched.stop()


def _port(url: str) -> int:
    return int(url.rsplit(":", 1)[1].split("/")[0])


def run(args, wanted, by_service, services, run_id, started, out_dir) -> int:
    mh = mws_health(args.mws)
    if "error" in mh:
        print(f"MWS is not reachable at {args.mws}: {mh['error']}\nStart it with `MWS_LISTEN=127.0.0.1:{_port(args.mws)} cargo run -p mws` or pass --start-mws.", file=sys.stderr)
        return 2
    if args.self_test:
        lh = {"edition": "mws (self-test)", "health": mws_health(args.localstack)}
        args.localstack_key, args.localstack_secret = args.mws_key, args.mws_secret
    else:
        lh = localstack_health(args.localstack)
    if "error" in lh:
        print(f"LocalStack is not reachable at {args.localstack}: {lh['error']}\nStart it (`localstack start`) or pass --start-localstack.", file=sys.stderr)
        return 2
    li = {} if args.self_test else localstack_info(args.localstack)
    mws = Target("mws", args.mws, args.mws_key, args.mws_secret, args.region)
    ls = Target("localstack", args.localstack, args.localstack_key, args.localstack_secret, args.region)

    def op_filter(case: Case) -> bool:
        if args.operation and case.operation not in args.operation:
            return False
        if args.case and not any(fnmatch.fnmatchcase(case.id, pat) for pat in args.case):
            return False
        return True

    flt = op_filter if (args.case or args.operation) else None
    kinds = {"all": {"read", "validation"}, "probes": {"read", "validation"}, "read": {"read"}, "validation": {"validation"}}.get(args.mode, set())
    do_scenarios = args.mode in ("all", "scenarios")
    lock = threading.Lock()
    status: dict[str, dict] = {}
    all_cases: list[Case] = []

    def log(msg):
        with lock:
            print(msg, flush=True)

    def one(service: str):
        sr = ServiceRun(service, services[service], mws, ls, run_id, lh, flt, log, args.keep_matches)
        sr.check_localstack_offers()
        if sr.localstack_absent:
            return service, sr, {"status": "skipped", "reason": sr.localstack_absent}
        if do_scenarios:
            for i, sc in enumerate(by_service.get(service, []), 1):
                if sr.localstack_absent:
                    break
                try:
                    sr.run_scenario(sc, i)
                except Exception:  # noqa: BLE001 - keep going, report the crash
                    log(f"[{service}] scenario {sc.title!r} crashed:\n{traceback.format_exc()}")
        if kinds and not sr.localstack_absent:
            sr.run_probes(kinds)
        if sr.localstack_absent:
            return service, sr, {"status": "skipped", "reason": sr.localstack_absent}
        return service, sr, {"status": "compared", "reason": ""}

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = [pool.submit(one, s) for s in wanted]
        for fut in as_completed(futures):
            service, sr, st = fut.result()
            status[service] = st
            all_cases += sr.cases
            counts = {}
            for c in sr.cases:
                counts[c.outcome] = counts.get(c.outcome, 0) + 1
            log(f"[{service}] {st['status']}{': ' + st['reason'] if st['reason'] else ''} {counts}")

    all_cases.sort(key=lambda c: c.id)
    meta = {
        "run_id": run_id,
        "started": started.isoformat(),
        "finished": dt.datetime.now(dt.timezone.utc).isoformat(),
        "command": "python -m parity " + " ".join(shlex.quote(a) for a in args.argv),
        "mode": args.mode,
        "mws": {"endpoint": args.mws, "health": mh},
        "localstack": {
            "endpoint": args.localstack,
            "edition": lh.get("edition"),
            "version": lh.get("version"),
            "health": lh,
            "info": li,
        },
        "normalization": "run id -> <run>, endpoints -> <endpoint>, UUIDs, timestamps, 12-digit accounts, AWS resource ids, long hex and opaque tokens -> placeholders; digests (MD5/ETag/SHA) kept",
    }
    report.write(out_dir, meta, all_cases, services, status, args.keep_matches)
    counts = {}
    for c in all_cases:
        counts[c.outcome] = counts.get(c.outcome, 0) + 1
    mws_wrong = sum(1 for c in all_cases if c.verdict and c.verdict.likely_wrong in ("mws", "both"))
    print(f"\n{len(all_cases)} calls compared: {counts}; MWS likely wrong in {mws_wrong}")
    print(f"report: {out_dir / 'report.md'}")
    if args.fail_on == "disparity" and counts.get("disparity"):
        return 1
    if args.fail_on == "mws" and mws_wrong:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
