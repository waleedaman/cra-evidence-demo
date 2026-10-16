# SPDX-License-Identifier: Apache-2.0
"""Review and sign decision drafts, one at a time: make review REVIEWER="Jane Doe" [VULN=<id>]

  python -m pipeline.review --out-dir out/v1.0/<board> --board <board> --version v1.0 \
                            --reviewer "Jane Doe" [--vuln CVE-...]

For every draft of this release and board (a decision file that does not pass the schema
only because reviewer / decided_at are empty) it shows the finding, the proposed status,
the justification and the evidence, and asks: sign, skip or quit. Signing writes the
reviewer's name, the UTC time and the binding to the firmware that is built now; nothing
else in the file changes. Text edits are made in the YAML file itself, before signing.

The reviewer is a person: the name is checked against the same rule as the gate (R5).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from pipeline import decisions
from pipeline.common import REPO, console

POLICY_FILE = REPO / "policy" / "gate.yaml"
SIGN_FIELDS = {"reviewer", "decided_at"}
DRAFT_HEADER = re.compile(r"^# DRAFT prepared (\S+) by (.+?) for review\..*?\n(?:#.*\n)*?"
                          r"# with `make review.*\n", re.M)


def blocking_errors(d: decisions.Decision) -> list[str]:
    """Schema errors other than the two fields that signing fills in."""
    return [e for e in d.errors
            if not any(e.startswith(f"{f}:") for f in SIGN_FIELDS)
            and not any(f"'{f}'" in e for f in SIGN_FIELDS)]


def reviewer_ok(name: str) -> bool:
    policy: dict[str, Any] = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    pattern = policy["rules"]["decision_quality"].get("reviewer_not_matching", "$^")
    return bool(name.strip()) and not re.search(pattern, name, re.I)


def show(d: decisions.Decision, i: int, n: int, finding: dict[str, Any] | None,
         product: dict[str, Any]) -> None:
    sev = (finding or {}).get("severity") or d.get("finding", "severity") or "?"
    t = Table.grid(padding=(0, 1))
    t.add_column(style="bold", no_wrap=True)
    t.add_column()
    t.add_row("Status", f"[bold]{d.get('status')}[/]"
              + (f"  ({d.get('justification')})" if d.get("justification") else ""))
    for key in ("impact_statement", "action_statement", "due_date"):
        if d.get(key):
            t.add_row(key.split("_")[0].capitalize(), escape(str(d.get(key))))
    for e in d.get("evidence") or []:
        if e.get("type") in ("scanner-report", "advisory"):
            continue
        desc = re.sub(r"\s*\(make [^)]*\)", "", str(e.get("description")))
        t.add_row(f"  {e.get('type')}", escape(desc)[:200])
    adv = sum(1 for e in d.get("evidence") or [] if e.get("type") == "advisory")
    t.add_row("  +", f"scanner report, {adv} advisory link(s)")
    t.add_row("Reassess if", escape(str(d.get("reassess_trigger"))))
    bound = d.get("product", "firmware_sha256")
    if bound != product["firmware_sha256"]:
        t.add_row("[yellow]Binding[/]", f"[yellow]prepared for firmware {str(bound)[:12]}, "
                  f"signing binds it to the current build {product['firmware_sha256'][:12]}[/]")
    console.print(Panel(t, title=f"[{i}/{n}] {d.get('vuln_id')}  {d.get('component')}  [{sev}]",
                        subtitle=d.path.name, expand=True))


def set_product(text: str, key: str, value: str) -> str:
    """Replace the value of one two-space indented key (the product block)."""
    m = re.search(rf"^  {key}: .*$", text, re.M)
    return text if m is None else text[:m.start()] + f"  {key}: {value}" + text[m.end():]


def sign(d: decisions.Decision, reviewer: str, product: dict[str, Any]) -> None:
    text = d.path.read_text(encoding="utf-8")
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    m = DRAFT_HEADER.search(text)
    note = f"# Reviewed and signed by {reviewer} at {now} (make review).\n"
    if m:
        note = f"# Prepared {m.group(1)} by {m.group(2)}; reviewed and signed by {reviewer} at {now} (make review).\n"
        text = text[:m.start()] + note + text[m.end():]
    else:
        text = re.sub(r"^(vuln_id:)", note + r"\1", text, count=1, flags=re.M)
    text = re.sub(r'^reviewer: .*$', f"reviewer: {json.dumps(reviewer, ensure_ascii=False)}", text,
                  count=1, flags=re.M)
    text = re.sub(r'^decided_at: .*$', f'decided_at: "{now}"', text, count=1, flags=re.M)
    for key in ("version", "firmware_file", "firmware_sha256", "purl"):
        text = set_product(text, key, json.dumps(product[key]))
    d.path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--reviewer", default="")
    parser.add_argument("--vuln", default="")
    args = parser.parse_args(argv)

    if not reviewer_ok(args.reviewer):
        console.print("[bold red]usage: make review VERSION=... REVIEWER=\"<your name>\"[/]  "
                      "(a person; tool and AI names are rejected, see policy/gate.yaml)")
        return 2
    if not sys.stdin.isatty():
        console.print("[bold red]make review is interactive: run it in a terminal[/]")
        return 2
    findings = json.loads((args.out_dir / "findings.json").read_text(encoding="utf-8"))
    product = findings["product"]
    folder = decisions.file_for(args.version, args.board, "x", "x").parent
    drafts = [d for d in (decisions.load(p) for p in sorted(folder.glob("*.yaml")))
              if not d.valid and (not args.vuln or args.vuln in decisions.ids_of(d))]
    if not drafts:
        console.print(f"no drafts in {folder.relative_to(REPO)}"
                      + (f" for {args.vuln}" if args.vuln else ""))
        return 0
    by_key = {(f["id"], f["component"]): f for f in findings["findings"]}
    signed = skipped = 0
    for i, d in enumerate(drafts, start=1):
        show(d, i, len(drafts), by_key.get((str(d.get("vuln_id")), str(d.get("component")))), product)
        errs = blocking_errors(d)
        if errs:
            console.print(f"[yellow]cannot be signed yet, complete first: {escape(d.todo)}[/]")
            skipped += 1
            continue
        try:
            answer = input(f"Sign as {args.reviewer}?  [y]es  [n]o, skip  [q]uit: ").strip().lower()
        except EOFError:
            answer = "q"
        if answer == "q":
            break
        if answer != "y":
            skipped += 1
            continue
        sign(d, args.reviewer, product)
        if not decisions.load(d.path).valid:
            console.print(f"[bold red]{d.path.name} still does not pass the schema[/]")
            return 1
        signed += 1
        console.print(f"[green]signed {d.path.name}[/]")
    left = len(drafts) - signed
    console.print(f"[bold]{signed} signed, {left} left as draft[/] in {folder.relative_to(REPO)}. "
                  "Next: make queue, make vex SIGN=1, make gate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
