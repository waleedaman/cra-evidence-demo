# SPDX-License-Identifier: Apache-2.0
"""Scaffold decision files from findings, pre-filled with facts only.

  python -m pipeline.decide --out-dir out/v1.0/<board> --board <board> --version v1.0 \
                            --vuln CVE-2023-4039 [--component gcc] [--force]
  python -m pipeline.decide ... --vuln open      # one draft per open finding without a file
  python -m pipeline.decide ... --vuln open --from v1.0   # carry decisions of v1.0 forward

--from <release> starts from the decisions of an earlier release of the same board instead
of an empty scaffold: the text is copied, the product binding is moved to this build, and
reviewer and decided_at are cleared, so each one needs a new review. Kconfig conditions in
reassess_trigger ("CONFIG_NET_IPV6=y") are checked against this build's .config; a trigger
that now holds is marked in the file and in the table (scenario 4).

The scaffold copies what the scan knows (IDs, component, product binding, advisory links,
the scanner's match) and leaves everything that needs judgement empty: status stays
under_investigation without a due date, reviewer and decided_at are empty. Such a file
does not pass schema/decision.schema.json, so `make queue` shows it as "draft" and
`make vex` refuses to build until a person completes it. See docs/decisions.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.markup import escape
from rich.table import Table

from pipeline import decisions
from pipeline.common import REPO, console
from pipeline.queue import classify, cross_check

TEMPLATE = """\
# Decision: {vuln} in {component} | {release} | {board}
# Scaffolded {today} by `make decide` from {findings} (snapshot {snapshot}).
# Complete status and the fields it requires, evidence, reviewer, decided_at and
# reassess_trigger. Until the file passes schema/decision.schema.json it is a draft:
# make queue lists it as "draft", make vex refuses to build. Guide: docs/decisions.md

vuln_id: {vuln_q}
aliases: {aliases}
component: {component_q}
{component_id}
product:
  name: {p_name}
  version: {p_version}
  board: {p_board}
  purl: {p_purl}
  firmware_file: {p_file}
  firmware_sha256: {p_sha}

# not_affected | affected | fixed | under_investigation
status: under_investigation
# not_affected only, one of: component_not_present, vulnerable_code_not_present,
#   vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary,
#   inline_mitigations_already_exist
justification: null
# not_affected (required): why THIS firmware is not affected
impact_statement: null
# affected (required): what is done / what users must do
action_statement: null
# under_investigation (required): date the investigation must be finished, YYYY-MM-DD
due_date: null

# What the decision rests on. Scanner output alone never counts (Phase 7 gate).
# types: scanner-report, advisory, sbom, config, linker-map, symbols, source, commit,
#        test, analysis, other
evidence:
{evidence}
# The person responsible for this decision (a person, never a tool or an AI)
reviewer: ""
# UTC timestamp, e.g. 2026-10-15T14:00:00Z
decided_at: ""
# What would make this decision wrong, e.g. "CONFIG_IEEE802154 enabled"
reassess_trigger: ""
# Only to ship with an affected finding at or above the gate threshold
exception: null

# Context copied from the scan; not part of the decision
finding:
{finding}
"""


def q(value: Any) -> str:
    """JSON scalars are valid YAML flow scalars and need no escaping rules of their own."""
    return json.dumps(value, ensure_ascii=False)


def scanner_description(f: dict[str, Any]) -> str:
    parts = []
    if "grype" in f["found_by"]:
        g = f.get("grype", {})
        parts.append(f"Grype ({g.get('namespace')}) matched {', '.join(g.get('matched_cpes', []))} "
                     f"against \"{g.get('version_constraint')}\"")
    if "osv-scanner" in f["found_by"]:
        o = f.get("osv", {})
        parts.append(f"OSV-Scanner: OSV record lists {o.get('version')} of {o.get('repo')} as affected")
    if f.get("osv_view"):
        parts.append(f["osv_view"])
    return "; ".join(parts)


def render(f: dict[str, Any], findings: dict[str, Any], release: str, board: str,
           findings_path: str) -> str:
    p = findings["product"]
    cpes: list[str] = next((c["cpes"] for c in findings["coverage"]
                            if c["component"] == f["component"]), [])
    if f.get("component_purl"):
        comp_id = f"component_purl: {q(f['component_purl'])}"
    else:
        comp_id = (f"# no PURL for this component: identified by CPE\n"
                   f"component_cpe: {q(cpes[0] if cpes else None)}")
    ev = [("scanner-report", findings_path, scanner_description(f))]
    ev += [("advisory", u, "Reference listed with the finding") for u in f.get("urls", [])]
    evidence = "\n".join(f"  - type: {t}\n    path_or_url: {q(u)}\n    description: {q(d)}"
                         for t, u, d in ev)
    ctx = {"severity": f["severity"], "score": f.get("score"), "found_by": f["found_by"],
           "cross_check": cross_check(f), "snapshot": findings["snapshot"]["name"],
           "summary": f.get("summary", "")}
    if f.get("grype"):
        ctx["nvd_constraint"] = f["grype"].get("version_constraint")
    finding = "\n".join(f"  {k}: {q(v)}" for k, v in ctx.items())
    return TEMPLATE.format(
        vuln=f["id"], component=f["component"], release=release, board=board,
        today=datetime.now(UTC).strftime("%Y-%m-%d"), findings=findings_path,
        snapshot=findings["snapshot"]["name"], vuln_q=q(f["id"]), aliases=q(f.get("aliases", [])),
        component_q=q(f["component"]), component_id=comp_id, p_name=q(p["name"]),
        p_version=q(p["version"]), p_board=q(p["board"]), p_purl=q(p["purl"]),
        p_file=q(p["firmware_file"]), p_sha=q(p["firmware_sha256"]),
        evidence=evidence, finding=finding)


TRIGGER = re.compile(r"(CONFIG_[A-Z0-9_]+)=(\S+?)(?=$|[\s,;)])")


def config_values(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("CONFIG_") and "=" in line:
                k, v = line.split("=", 1)
                vals[k] = v.strip('"')
    return vals


def triggers_hit(trigger: str, config: dict[str, str]) -> list[str]:
    """Kconfig conditions of a reassess_trigger that hold in this build ('n' = unset)."""
    hits = []
    for name, want in TRIGGER.findall(trigger):
        have = config.get(name, "n")
        if have == want:
            hits.append(f"{name}={want}")
    return hits


def set_product(text: str, key: str, value: str) -> str:
    """Replace the value of one two-space indented key (the product block)."""
    m = re.search(rf"^  {key}: .*$", text, re.M)
    return text if m is None else text[:m.start()] + f"  {key}: {value}" + text[m.end():]


def carry_forward(old: decisions.Decision, findings: dict[str, Any], from_release: str,
                  hits: list[str]) -> str:
    p = findings["product"]
    text = old.path.read_text(encoding="utf-8")
    body = text[text.index("vuln_id:"):]
    body = re.sub(r'^reviewer: .*$', 'reviewer: ""', body, count=1, flags=re.M)
    body = re.sub(r'^decided_at: .*$', 'decided_at: ""', body, count=1, flags=re.M)
    for key in ("version", "firmware_file", "firmware_sha256", "purl"):
        body = set_product(body, key, q(p[key]))
    head = (f"# Decision: {old.get('vuln_id')} in {old.get('component')} | {p['release']} | {p['board']}\n"
            f"# Carried forward {datetime.now(UTC).strftime('%Y-%m-%d')} from {old.rel} "
            f"(make decide FROM={from_release}).\n"
            "# NOT reviewed for this build: reviewer and decided_at are empty until a person\n"
            "# re-checks the evidence for THIS firmware (make review). Guide: docs/decisions.md\n")
    if hits:
        head += (f"# REASSESS: the trigger {', '.join(hits)} holds in {p['release']}. The old\n"
                 "# justification is probably wrong for this build: redo the analysis.\n")
    return head + body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--vuln", required=True, help="vulnerability ID, or 'open'")
    parser.add_argument("--component", default="")
    parser.add_argument("--force", action="store_true", help="overwrite an existing file")
    parser.add_argument("--from", dest="from_release", default="",
                        help="carry decisions forward from this earlier release")
    args = parser.parse_args(argv)

    src = args.out_dir / "findings.json"
    if not src.exists():
        console.print(f"[bold red]{src} missing: run make scan first[/]")
        return 1
    findings = json.loads(src.read_text(encoding="utf-8"))
    if findings["product"]["release"] != args.version:
        console.print(f"[bold red]{src} is for {findings['product']['release']}[/]")
        return 1
    if args.vuln == "open":
        open_keys = {(it["id"], it["component"]) for it in classify(findings, decisions.load_all())}
        selected = [f for f in findings["findings"] if (f["id"], f["component"]) in open_keys]
    else:
        selected = [f for f in findings["findings"]
                    if args.vuln in {f["id"], *f.get("aliases", [])}
                    and (not args.component or f["component"] == args.component)]
        if not selected:
            console.print(f"[bold red]{escape(args.vuln)} is not a finding of this build[/]")
            return 1
        if len(selected) > 1:
            names = ", ".join(f["component"] for f in selected)
            console.print(f"[bold red]{args.vuln} affects several components ({names}): "
                          "add COMPONENT=<name>[/]")
            return 1

    folder = decisions.file_for(args.version, args.board, "x", "x").parent
    if args.from_release:
        return main_from(args, findings, selected, folder)
    table = Table(title=f"make decide  |  {folder.relative_to(REPO)}/")
    table.add_column("Vulnerability", no_wrap=True)
    table.add_column("Component")
    table.add_column("File")
    table.add_column("Result")
    created = 0
    for f in selected:
        path = decisions.file_for(args.version, args.board, f["id"], f["component"])
        rel = path.name
        if path.exists() and not args.force:
            table.add_row(f["id"], f["component"], rel, "[yellow]exists, kept[/]")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render(f, findings, args.version, args.board, str(src)), encoding="utf-8")
        created += 1
        table.add_row(f["id"], f["component"], rel, "[green]draft written[/]")
    if len(selected) <= 15:
        console.print(table)
    console.print(f"{created} draft(s) written. Edit them, then: make queue / make vex")
    return 0


def main_from(args: argparse.Namespace, findings: dict[str, Any], selected: list[dict[str, Any]],
              folder: Path) -> int:
    config = config_values(args.out_dir / "config")
    rows: list[tuple[str, str, str, str, str]] = []
    created = 0
    for f in selected:
        path = decisions.file_for(args.version, args.board, f["id"], f["component"])
        if path.exists() and not args.force:
            rows.append((f["id"], f["component"], "-", "exists, kept", ""))
            continue
        old_path = decisions.file_for(args.from_release, args.board, f["id"], f["component"])
        path.parent.mkdir(parents=True, exist_ok=True)
        if old_path.exists():
            old = decisions.load(old_path)
            hits = triggers_hit(str(old.get("reassess_trigger") or ""), config)
            path.write_text(carry_forward(old, findings, args.from_release, hits), encoding="utf-8")
            rows.append((f["id"], f["component"], str(old.get("status")),
                         "carried, needs review",
                         hits[0] + (f" (+{len(hits) - 1})" if len(hits) > 1 else "") if hits else ""))
        else:
            path.write_text(render(f, findings, args.version, args.board,
                                   str(args.out_dir / "findings.json")), encoding="utf-8")
            rows.append((f["id"], f["component"], "-", "new draft", ""))
        created += 1
    rows.sort(key=lambda r: (not r[4], r[3] != "new draft"))
    hit = sum(1 for r in rows if r[4])
    table = Table(title=f"make decide FROM={args.from_release}  |  {folder.relative_to(REPO)}/")
    table.add_column("Vulnerability", no_wrap=True)
    table.add_column("Component")
    table.add_column(f"{args.from_release} status")
    table.add_column("Result")
    table.add_column("Reassess trigger holds", style="bold red")
    for r in rows[:8]:
        table.add_row(*r)
    console.print(table)
    console.print(f"{created} draft(s) written ({max(len(rows) - 8, 0)} more rows not shown). [bold red]{hit} decision(s) whose reassess trigger now holds.[/] "
                  "Every carried decision needs a new review: make review")
    return 0


if __name__ == "__main__":
    sys.exit(main())
