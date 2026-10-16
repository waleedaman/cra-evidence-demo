# SPDX-License-Identifier: Apache-2.0
"""Release gate: may THIS firmware build be released? PASS or FAIL per rule of policy/gate.yaml.

  python -m pipeline.gate --out-dir out/v1.0/<board> --board <board> --version v1.0 [--soft]

Reads only files the earlier steps wrote (normalized SBOM, provenance bundle, findings.json,
decisions/, vex/) and checks them against each other. Nothing is re-scanned here.
GATE_DATE=YYYY-MM-DD evaluates due dates, exception expiry and snapshot age at that date
(rehearsing the talk date); default is today (UTC).

Writes out/<v>/<board>/gate.json. Exit code 1 on FAIL (0 with --soft, for the scenarios).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.table import Table

from pipeline import decisions
from pipeline.common import REPO, console, run, sha256_file
from pipeline.queue import classify
from pipeline.scan import SEVERITY_RANK

POLICY_FILE = REPO / "policy" / "gate.yaml"
NORMALIZED = Path("normalized") / "firmware.spdx.json"
VEX_FILE = Path("vex") / "firmware.openvex.json"
VEX_BUNDLE = Path("vex") / "firmware.openvex.sigstore.json"
PUBKEY = REPO / "keys" / "cosign.pub"


@dataclass
class Rule:
    key: str
    title: str
    ok: bool = True
    detail: str = ""
    items: list[str] = field(default_factory=list)   # blocking items, one line each

    def fail(self, item: str) -> None:
        self.ok = False
        self.items.append(item)


def gate_date() -> date:
    raw = os.environ.get("GATE_DATE", "")
    return date.fromisoformat(raw) if raw else datetime.now(UTC).date()


def parse_day(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def at_or_above(sev: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK[threshold]


def r1_sbom(out_dir: Path) -> Rule:
    from pipeline import validate   # heavy import (spdx-tools, checker): only when needed
    r = Rule("sbom_valid", "R1 SBOM valid (SPDX 2.3, NTIA)")
    path = out_dir / NORMALIZED
    if not path.exists():
        r.fail(f"{NORMALIZED} missing (make normalize)")
        return r
    res = validate.check(path)
    if res.spdx_errors:
        r.fail(f"{len(res.spdx_errors)} SPDX errors, first: {res.spdx_errors[0][:70]}")
    if not res.ntia.compliant:
        r.fail("NTIA minimum elements: " + ", ".join(res.ntia.failed)[:80])
    r.detail = f"{res.packages} packages, {res.with_ids} with CPE/PURL" if r.ok else ""
    return r


def r2_provenance(out_dir: Path) -> Rule:
    from pipeline.provenance import verify_rows
    r = Rule("provenance_verified", "R2 Provenance signed and verified")
    rows = verify_rows(out_dir, PUBKEY)
    for name, actual, ok in rows:
        if not ok:
            r.fail(f"{name}: {actual}")
    r.detail = f"{len(rows)} checks" if r.ok else ""
    return r


def r3_findings(out_dir: Path, f: dict[str, Any], cfg: dict[str, Any], today: date) -> Rule:
    r = Rule("findings_current", "R3 Findings current for this build")
    p = f["product"]
    fw = out_dir / p["firmware_file"]
    if not fw.exists() or sha256_file(fw) != p["firmware_sha256"]:
        r.fail(f"findings.json is for firmware {p['firmware_sha256'][:12]}, not {fw.name} on disk")
    sbom = out_dir / NORMALIZED
    if not sbom.exists() or sha256_file(sbom) != f["sbom"]["sha256"]:
        r.fail("findings.json was made from another SBOM: run make scan again")
    snap = f["snapshot"]
    built = parse_day(snap["grype"].get("built", "")) or today
    age = (today - built).days
    limit = int(cfg.get("max_snapshot_age_days", 60))
    if age > limit:
        r.fail(f"snapshot '{snap['name']}' is {age} days old (max {limit}): make snapshot + make scan")
    synth = snap.get("synthetic_osv_records") or []
    parts = [f"snapshot '{snap['name']}', {age} days old"] if r.ok else []
    if synth:
        parts.append(f"+ {len(synth)} SYNTHETIC record(s)")
    r.detail = ", ".join(parts)
    return r


def r4_decided(f: dict[str, Any], ds: list[decisions.Decision]) -> tuple[Rule, list[dict[str, Any]]]:
    r = Rule("every_finding_decided", "R4 Every finding has a decision")
    open_items = classify(f, ds)
    for it in open_items:
        why = {"new": "no decision", "draft": "draft (" + "; ".join(it["draft_errors"])[:50] + ")",
               "stale": "decision for another build only"}[it["state"]]
        r.fail(f"{it['id']} {it['component']} [{it['severity']}]: {why}")
    r.detail = (f"{len(f['findings'])} findings, all decided" if r.ok else
                f"{len(open_items)} of {len(f['findings'])} findings without decision")
    return r, open_items


def r5_quality(bound: list[decisions.Decision], cfg: dict[str, Any]) -> Rule:
    r = Rule("decision_quality", "R5 Decisions: reviewer + evidence")
    weak = set(cfg.get("insufficient_evidence_types", ["scanner-report"]))
    pattern = re.compile(cfg.get("reviewer_not_matching", "$^"), re.I)
    for d in bound:
        if not d.valid:
            continue   # reported by R4
        name = d.path.name.removesuffix(".yaml")
        reviewer = str(d.get("reviewer") or "")
        if pattern.search(reviewer):
            r.fail(f"{name}: reviewer '{reviewer}' is not a person")
        types = {str(e.get("type")) for e in d.get("evidence") or []}
        if types <= weak:
            r.fail(f"{name}: only {', '.join(sorted(types))} evidence")
    r.detail = f"{sum(1 for d in bound if d.valid)} valid decisions checked" if r.ok else ""
    return r


def finding_index(f: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(x["id"], x["component"]): x for x in f["findings"]}


def severity_of(d: decisions.Decision, f: dict[str, Any]) -> str:
    for x in f["findings"]:
        if decisions.covers(d, x, f["product"]):
            return str(x["severity"])
    return str(d.get("finding", "severity") or "Unknown")


def r6_affected(bound: list[decisions.Decision], f: dict[str, Any], threshold: str, today: date) -> Rule:
    r = Rule("no_unaccepted_affected", f"R6 No affected >= {threshold} without exception")
    n = 0
    for d in bound:
        if not d.valid or d.get("status") != "affected":
            continue
        n += 1
        sev = severity_of(d, f)
        if not at_or_above(sev, threshold):
            continue
        ex = d.get("exception") or {}
        expires = parse_day(ex.get("expires"))
        label = f"{d.get('vuln_id')} {d.get('component')} [{sev}] affected"
        if not ex or not ex.get("approved_by"):
            r.fail(f"{label}, no approved exception")
        elif expires is None or expires < today:
            r.fail(f"{label}, exception expired {ex.get('expires')}")
    r.detail = f"{n} affected, none blocking" if r.ok else ""
    return r


def r7_investigations(bound: list[decisions.Decision], f: dict[str, Any], threshold: str,
                      today: date) -> Rule:
    r = Rule("investigations_in_time", "R7 Investigations below threshold, in time")
    n = 0
    for d in bound:
        if not d.valid or d.get("status") != "under_investigation":
            continue
        n += 1
        sev = severity_of(d, f)
        label = f"{d.get('vuln_id')} {d.get('component')} [{sev}]"
        due = parse_day(d.get("due_date"))
        if at_or_above(sev, threshold):
            r.fail(f"{label}: still under investigation (>= {threshold})")
        elif due is None or due < today:
            r.fail(f"{label}: investigation overdue since {d.get('due_date')}")
    r.detail = f"{n} under investigation" if r.ok else ""
    return r


def r8_vex(out_dir: Path, bound: list[decisions.Decision], product: dict[str, Any],
           cfg: dict[str, Any]) -> Rule:
    r = Rule("vex_current", "R8 OpenVEX current and signed")
    path = out_dir / VEX_FILE
    if not path.exists():
        r.fail("no OpenVEX document (make vex SIGN=1)")
        return r
    vex = json.loads(path.read_text(encoding="utf-8"))
    stmts = vex.get("statements", [])
    wrong = [s for s in stmts if not any(product["firmware_sha256"] in str(p.get("@id", ""))
                                         for p in s.get("products", []))]
    if wrong:
        r.fail(f"{len(wrong)} statements for another firmware")
    have = {(s["vulnerability"]["name"], s["status"]) for s in stmts}
    want = {(str(d.get("vuln_id")), str(d.get("status"))) for d in bound if d.valid}
    for vid, st in sorted(want - have):
        r.fail(f"decision {vid} ({st}) not in VEX: make vex")
    for vid, st in sorted(have - want):
        r.fail(f"VEX says {vid} {st}, no such decision now: make vex")
    if cfg.get("require_signed", True):
        bundle = out_dir / VEX_BUNDLE
        if not bundle.exists():
            r.fail("VEX not signed (make vex SIGN=1)")
        else:
            res = run(["cosign", "verify-blob", "--key", str(PUBKEY), "--bundle", str(bundle),
                       "--insecure-ignore-tlog=true", str(path)])
            if not res.ok:
                r.fail("VEX signature does not verify")
    r.detail = f"{len(stmts)} statements, signed" if r.ok else ""
    return r


def evaluate(out_dir: Path, board: str, version: str, policy: dict[str, Any],
             policy_path: Path = POLICY_FILE) -> dict[str, Any]:
    today = gate_date()
    rules_cfg: dict[str, Any] = policy["rules"]
    threshold = str(policy["severity_threshold"])
    f = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
    product = f["product"]
    ds = decisions.load_all()
    bound = [d for d in ds if d.path.parent == decisions.file_for(version, board, "x", "x").parent
             and d.get("product", "firmware_sha256") == product["firmware_sha256"]
             and d.get("product", "version") == product["version"]]

    def cfg(key: str) -> dict[str, Any] | None:
        value = rules_cfg.get(key, False)
        if value is False or value is None:
            return None
        return value if isinstance(value, dict) else {}

    rules: list[Rule] = []
    if cfg("sbom_valid") is not None:
        rules.append(r1_sbom(out_dir))
    if cfg("provenance_verified") is not None:
        rules.append(r2_provenance(out_dir))
    if (c := cfg("findings_current")) is not None:
        rules.append(r3_findings(out_dir, f, c, today))
    open_items: list[dict[str, Any]] = []
    if cfg("every_finding_decided") is not None:
        r4, open_items = r4_decided(f, ds)
        rules.append(r4)
    if (c := cfg("decision_quality")) is not None:
        rules.append(r5_quality(bound, c))
    if cfg("no_unaccepted_affected") is not None:
        rules.append(r6_affected(bound, f, threshold, today))
    if cfg("investigations_in_time") is not None:
        rules.append(r7_investigations(bound, f, threshold, today))
    if (c := cfg("vex_current")) is not None:
        rules.append(r8_vex(out_dir, bound, product, c))

    return {
        "schema": "cra-evidence-demo/gate/v1",
        "result": "PASS" if all(r.ok for r in rules) else "FAIL",
        "evaluated_for": today.isoformat(),
        "policy": str(policy_path.resolve().relative_to(REPO)),
        "policy_sha256": sha256_file(policy_path),
        "severity_threshold": threshold,
        "product": product,
        "snapshot": f["snapshot"]["name"],
        "findings": len(f["findings"]),
        "open_findings": len(open_items),
        "decisions_bound": len(bound),
        "rules": [{"rule": r.key, "title": r.title, "ok": r.ok, "detail": r.detail,
                   "blocking": r.items} for r in rules],
    }


def render(report: dict[str, Any], rows: int) -> None:
    p = report["product"]
    t = Table(title=f"make gate  |  {p['release']}  |  {p['board']}  |  firmware "
                    f"{p['firmware_sha256'][:12]}  |  {report['evaluated_for']}")
    t.add_column("Rule", no_wrap=True)
    t.add_column("Result", no_wrap=True)
    t.add_column("Detail")
    for r in report["rules"]:
        detail = r["detail"] or f"{len(r['blocking'])} blocking"
        t.add_row(r["title"], "[bold green]PASS[/]" if r["ok"] else "[bold red]FAIL[/]",
                  escape(detail[:70]))
    console.print(t)
    blocking = [(r["rule"], b) for r in report["rules"] for b in r["blocking"]]
    if blocking:
        shown = blocking[:rows]
        bt = Table(title=f"Blocking items ({len(shown)} of {len(blocking)}, all in gate.json)")
        bt.add_column("Rule", no_wrap=True)
        bt.add_column("Item")
        for rule, item in shown:
            bt.add_row(rule, escape(item if len(item) <= 70 else item[:67] + '...'))
        console.print(bt)
    style = "bold green" if report["result"] == "PASS" else "bold red"
    console.print(f"[{style}]GATE {report['result']}[/]   policy {report['policy']} "
                  f"(threshold {report['severity_threshold']}), {report['findings']} findings, "
                  f"{report['decisions_bound']} decisions bound to this firmware")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--policy", type=Path, default=POLICY_FILE)
    parser.add_argument("--rows", type=int, default=8)
    parser.add_argument("--soft", action="store_true", help="exit 0 on FAIL (scenarios)")
    args = parser.parse_args(argv)
    if not (args.out_dir / "findings.json").exists():
        console.print(f"[bold red]{args.out_dir}/findings.json missing: run make scan first[/]")
        return 1
    policy: dict[str, Any] = yaml.safe_load(args.policy.read_text(encoding="utf-8"))
    report = evaluate(args.out_dir, args.board, args.version, policy, args.policy)
    (args.out_dir / "gate.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    render(report, args.rows)
    return 0 if report["result"] == "PASS" or args.soft else 1


if __name__ == "__main__":
    sys.exit(main())
