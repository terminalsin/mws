#!/usr/bin/env python3
"""Decide what CI builds and tests for a change.

Reads the workspace graph from `cargo metadata` and the changed files from
`git diff`, then writes GitHub Actions outputs:

  full          "true" when everything runs (push to master, nightly, manual
                runs, and changes to shared crates or the build itself)
  rust          "true" when any Rust code has to be built
  fmt           "true" when `cargo fmt --check` has to run
  clippy        cargo package arguments for Clippy ("" for none)
  test_packages cargo package arguments for the test build
  matrix        the test matrix, JSON: {"include": [{"name", "filter"}]},
                one entry for unit tests and one per shard of e2e services
  python, ts    "true" when the boto3 / SDK for JavaScript suites must run

Usage: plan.py [--full] [--base REV]   (or --explain-modules to show how
end-to-end test modules map to service crates).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
E2E_PACKAGE = "mws-e2e"
# The crate that wires every service into the binary. Most service changes
# touch it (registration, cross-service links), so it does not force a full
# run; a change to it runs every end-to-end test instead.
GLUE_PACKAGE = "mws"
E2E_MODULES = ROOT / "tests/e2e-rust/tests/e2e"

# Files outside any crate that never affect the build.
DOC_PATTERNS = [r"^docs/", r"\.md$", r"^LICENSE", r"^\.gitignore$"]
# Files outside any crate that change how everything builds or runs.
GLOBAL_PATTERNS = [r"^\.github/", r"^rust-toolchain", r"^\.cargo/", r"^\.config/", r"^rustfmt\.toml$", r"^clippy\.toml$"]

# End-to-end modules are matched to service crates by name (`sqs`,
# `lambda_sqs`, `s3_parity`, ...). These cover module names that do not
# contain the crate's name.
MODULE_ALIASES = {
    "mws-elb": ["elbv2", "elb"],
    "mws-iam-policy": ["policies"],
    "mws-marketplace-entitlement": ["marketplace"],
    "mws-marketplace-metering": ["marketplace"],
    "mws-s3control": ["s3_control", "s3_batch", "object_lambda"],
    "mws-lambda": ["object_lambda"],
    "mws-ses": ["ses_v1", "ses_v2"],
}

# A shard holds about this much test weight (one per test, more for tests
# that start containers), and there are at most MAX_SHARDS of them.
SHARD_WEIGHT = 110
MAX_SHARDS = 4


def run(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True).stdout


def workspace() -> dict[str, dict]:
    """name -> {dir, deps (workspace deps of any kind), service}"""
    meta = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1"))
    names = {p["name"] for p in meta["packages"]}
    packages = {}
    for p in meta["packages"]:
        path = Path(p["manifest_path"]).parent.relative_to(ROOT).as_posix()
        packages[p["name"]] = {
            "dir": path,
            "deps": {d["name"] for d in p["dependencies"] if d["name"] in names},
            "service": path.startswith("crates/services/"),
        }
    return packages


def has_tests(directory: str) -> bool:
    pattern = re.compile(r"#\[(tokio::)?test\b")
    for file in (ROOT / directory).rglob("*.rs"):
        if "target" in file.parts:
            continue
        if pattern.search(file.read_text(errors="ignore")):
            return True
    return False


def reverse_closure(packages: dict[str, dict], changed: set[str]) -> set[str]:
    rdeps: dict[str, set[str]] = {name: set() for name in packages}
    for name, info in packages.items():
        for dep in info["deps"]:
            rdeps[dep].add(name)
    seen, todo = set(changed), list(changed)
    while todo:
        for parent in rdeps[todo.pop()]:
            if parent not in seen:
                seen.add(parent)
                todo.append(parent)
    return seen


def owner(packages: dict[str, dict], path: str) -> str | None:
    best = None
    for name, info in packages.items():
        d = info["dir"] + "/"
        if path.startswith(d) and (best is None or len(d) > len(packages[best]["dir"]) + 1):
            best = name
    return best


def file_at(rev: str, path: str) -> str | None:
    try:
        return run("git", "show", f"{rev}:{path}")
    except subprocess.CalledProcessError:
        return None


def root_manifest_is_global(base: str) -> bool:
    """Adding workspace members or internal path dependencies is local;
    any other change to the root Cargo.toml (versions, profiles, ...) is not."""
    old, new = file_at(base, "Cargo.toml"), (ROOT / "Cargo.toml").read_text()
    if old is None:
        return True

    def strip(text: str) -> dict:
        doc = tomllib.loads(text)
        ws = doc.get("workspace", {})
        ws.pop("members", None)
        deps = ws.get("dependencies", {})
        for k in [k for k, v in deps.items() if isinstance(v, dict) and "path" in v]:
            del deps[k]
        return doc

    return strip(old) != strip(new)


def lockfile_is_global(base: str) -> bool:
    """New packages in Cargo.lock only matter to the crates that added them
    (whose manifests changed too); an upgraded or removed one may matter to
    everything."""
    old = file_at(base, "Cargo.lock")
    if old is None:
        return True

    def external(text: str) -> set[tuple]:
        return {
            (p["name"], p["version"])
            for p in tomllib.loads(text).get("package", [])
            if "source" in p
        }

    return bool(external(old) - external((ROOT / "Cargo.lock").read_text()))


def module_weights() -> dict[str, int]:
    weights = {}
    for file in sorted(E2E_MODULES.glob("*.rs")):
        if file.stem == "main":
            continue
        text = file.read_text(errors="ignore")
        tests = len(re.findall(r"#\[(?:tokio::)?test\b", text))
        heavy = "docker" in file.stem or "kubernetes" in file.stem or "docker_available" in text
        weights[file.stem] = max(tests, 1) * (4 if heavy else 1)
    return weights


def module_services(packages: dict[str, dict], modules) -> dict[str, list[str]]:
    """Module -> the service crates its name refers to (empty: none)."""
    keys = {}
    for name, info in packages.items():
        if info["service"]:
            short = name.removeprefix("mws-").replace("-", "_")
            keys[name] = [short, *MODULE_ALIASES.get(name, [])]
    result = {}
    for module in modules:
        tokens = module.split("_")
        found = []
        for crate, names in keys.items():
            for key in names:
                parts = key.split("_")
                n = len(parts)
                if any(tokens[i : i + n] == parts for i in range(len(tokens) - n + 1)):
                    found.append(crate)
                    break
        result[module] = sorted(found)
    return result


def shards(selected: dict[str, list[str]], weights: dict[str, int]) -> list[dict]:
    """Group modules by their first service and pack the groups into shards."""
    groups: dict[str, list[str]] = {}
    for module, services in selected.items():
        label = services[0].removeprefix("mws-") if services else "cross-service"
        groups.setdefault(label, []).append(module)
    total = sum(weights[m] for m in selected)
    count = max(1, min(MAX_SHARDS, math.ceil(total / SHARD_WEIGHT), len(groups)))
    bins = [{"labels": [], "modules": [], "weight": 0} for _ in range(count)]
    for label, modules in sorted(groups.items(), key=lambda g: -sum(weights[m] for m in g[1])):
        target = min(bins, key=lambda b: b["weight"])
        target["labels"].append(label)
        target["modules"] += modules
        target["weight"] += sum(weights[m] for m in modules)
    out = []
    for i, b in enumerate(bins, 1):
        labels = sorted(b["labels"])
        name = ", ".join(labels[:4]) + (f" +{len(labels) - 4}" if len(labels) > 4 else "")
        alternatives = "|".join(sorted(b["modules"]))
        out.append(
            {
                "name": f"e2e {i}/{count}: {name}",
                "filter": f"package({E2E_PACKAGE}) and test(/^({alternatives})::/)",
            }
        )
    return out


def plan(full: bool, base: str | None) -> dict:
    packages = workspace()
    weights = module_weights()
    services_of = module_services(packages, weights)
    reasons: list[str] = []

    direct: set[str] = set()
    changed_modules: set[str] = set()
    python = ts = fmt = False
    if full:
        reasons.append("full run requested")
    else:
        files = [f for f in run("git", "diff", "--name-only", f"{base}...HEAD").splitlines() if f]
        for f in files:
            if f == "Cargo.toml":
                if root_manifest_is_global(base):
                    full = True
                    reasons.append("root Cargo.toml changed beyond workspace members")
                continue
            if f == "Cargo.lock":
                if lockfile_is_global(base):
                    full = True
                    reasons.append("Cargo.lock upgrades or removes a dependency")
                continue
            if any(re.search(p, f) for p in GLOBAL_PATTERNS):
                full = True
                reasons.append(f"{f} changed")
                continue
            if f.startswith("tests/e2e-python/"):
                python = True
                continue
            if f.startswith("tests/e2e-ts/"):
                ts = True
                continue
            crate = owner(packages, f)
            if crate is not None:
                direct.add(crate)
                if f.endswith(".rs"):
                    fmt = True
                if crate == E2E_PACKAGE:
                    p = Path(f)
                    if p.parent.as_posix() == E2E_MODULES.relative_to(ROOT).as_posix() and p.stem != "main":
                        changed_modules.add(p.stem)
                    elif p.parts[:3] == ("tests", "e2e-rust", "src"):
                        changed_modules.update(weights)
                continue
            if any(re.search(p, f) for p in DOC_PATTERNS):
                continue
            full = True
            reasons.append(f"{f} is outside every crate")

        if GLUE_PACKAGE in direct:
            changed_modules.update(weights)
        local = {E2E_PACKAGE, GLUE_PACKAGE}
        shared = sorted(c for c in direct if not packages[c]["service"] and c not in local)
        if shared and not full:
            full = True
            reasons.append("shared crate changed: " + ", ".join(shared))

    if full:
        names = set(packages)
        affected = names
        clippy = "--workspace"
        test_args = "--workspace"
        selected = dict(services_of)
        python = ts = fmt = True
    else:
        affected = reverse_closure(packages, direct)
        clippy = " ".join(f"-p {c}" for c in sorted(direct))
        testable = sorted(c for c in affected if c != E2E_PACKAGE and has_tests(packages[c]["dir"]))
        test_args = " ".join(f"-p {c}" for c in [*testable, E2E_PACKAGE]) if affected else ""
        changed_services = {c for c in affected if packages[c]["service"]}
        selected = {
            m: s
            for m, s in services_of.items()
            if m in changed_modules or set(s) & changed_services or (not s and changed_services)
        }

    rust = bool(affected)
    matrix = []
    if rust:
        unit_packages = [c for c in affected if c != E2E_PACKAGE and has_tests(packages[c]["dir"])]
        if unit_packages:
            matrix.append({"name": "unit tests", "filter": f"not package({E2E_PACKAGE})"})
        if selected:
            matrix += shards(selected, weights)
    return {
        "full": full,
        "rust": rust,
        "fmt": fmt or full,
        "clippy": clippy if rust else "",
        "test_packages": test_args if rust else "",
        "matrix": {"include": matrix},
        "python": python or rust,
        "ts": ts or rust,
        "reasons": reasons,
        "direct": sorted(direct),
        "affected": sorted(affected),
        "modules": sorted(selected),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--base")
    parser.add_argument("--explain-modules", action="store_true")
    args = parser.parse_args()

    if args.explain_modules:
        packages = workspace()
        for module, services in module_services(packages, module_weights()).items():
            print(f"{module:28} {' '.join(services) or '(every e2e run)'}")
        return
    if not args.full and not args.base:
        parser.error("pass --full or --base REV")

    result = plan(args.full, args.base)
    out = os.environ.get("GITHUB_OUTPUT")
    lines = []
    for key in ["full", "rust", "fmt", "clippy", "test_packages", "matrix", "python", "ts"]:
        value = result[key]
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif not isinstance(value, str):
            value = json.dumps(value, separators=(",", ":"))
        lines.append(f"{key}={value}")
    if out:
        with open(out, "a") as fh:
            fh.write("\n".join(lines) + "\n")

    summary = [
        "### CI plan",
        "",
        f"- Full run: **{result['full']}** {'(' + '; '.join(result['reasons']) + ')' if result['reasons'] else ''}",
        f"- Changed crates: {', '.join(result['direct']) or 'none'}",
        f"- Crates to test (with reverse dependencies): {len(result['affected'])}",
        f"- Clippy: `{result['clippy'] or 'skipped'}`",
        f"- End-to-end modules: {len(result['modules'])}",
        "",
        "| Job | Filter |",
        "| --- | --- |",
        *[f"| {m['name']} | `{m['filter']}` |" for m in result["matrix"]["include"]],
    ]
    print("\n".join(lines), file=sys.stderr)
    print("\n".join(summary))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write("\n".join(summary) + "\n")


if __name__ == "__main__":
    main()
