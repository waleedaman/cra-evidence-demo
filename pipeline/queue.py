# SPDX-License-Identifier: Apache-2.0
"""Review queue: findings without a human decision for THIS release and firmware hash.

  python -m pipeline.queue --out-dir out/v1.0/<board> --board <board> --version v1.0 [--rows 15]

Reads out/<v>/<board>/findings.json (make scan) and every decision file under
decisions/ (schema/decision.schema.json). A finding counts as decided only if a VALID
decision has the same vulnerability ID (or alias), the same component PURL (component
name when the component has no PURL), and product.version and product.firmware_sha256
equal to this build. Open states: "new" (no decision), "draft" (a decision file for this
firmware that does not pass the schema yet, e.g. no reviewer), "stale" (decisions only
for another version or firmware hash: a starting point, not coverage).

Writes the full list to out/<v>/<board>/queue.json and prints the first --rows entries.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rich.markup import escape
from rich.table import Table

from pipeline import decisions
from pipeline.common import console, sha256_file

SEV_STYLE = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "cyan"}


def cross_check(f: dict[str, Any]) -> str:
    if len(f["found_by"]) == 2:
        return "both scanners"
    if f["found_by"] == ["osv-scanner"]:
        return "Grype: no match"
    view = f.get("osv_view", "")
    if view.startswith("OSV record does not list"):
        return "OSV: not this version"
    return {"no OSV record": "OSV: no record",
            "OSV record for another repo": "OSV: other repo"}.get(view, "OSV: cannot check")


def classify(findings: dict[str, Any], all_decisions: list[decisions.Decision]) -> list[dict[str, Any]]:
    """Open items: new (no decision), draft (decision file for this firmware, not valid yet),
    stale (decisions exist, but for another version or firmware hash)."""
    product = findings["product"]
    items: list[dict[str, Any]] = []
    for f in findings["findings"]:
        ids = {f["id"], *f.get("aliases", [])}
        matching = [d for d in all_decisions
                    if decisions.ids_of(d) & ids and decisions.same_component(d, f)]
        if any(decisions.covers(d, f, product) for d in matching):
            continue
        bound = [d for d in matching if d.get("product", "firmware_sha256") == product["firmware_sha256"]
                 and d.get("product", "version") == product["version"]]
        state = "draft" if bound else "stale" if matching else "new"
        items.append({
            "id": f["id"], "component": f["component"], "component_purl": f.get("component_purl"),
            "severity": f["severity"], "found_by": f["found_by"], "cross_check": cross_check(f),
            "state": state,
            "draft_errors": [d.todo for d in bound if d.todo],
            "other_decisions": [{"file": d.rel, "version": d.get("product", "version"),
                                 "firmware_sha256": d.get("product", "firmware_sha256"),
                                 "status": d.get("status"), "valid": d.valid}
                                for d in matching if d not in bound],
        })
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--rows", type=int, default=15)
    args = parser.parse_args(argv)

    src = args.out_dir / "findings.json"
    if not src.exists():
        console.print(f"[bold red]{src} missing: run make scan first[/]")
        return 1
    findings = json.loads(src.read_text(encoding="utf-8"))
    product, snap = findings["product"], findings["snapshot"]
    if product["release"] != args.version:
        console.print(f"[bold red]{src} is for {product['release']}, not {args.version}[/]")
        return 1
    all_decisions = decisions.load_all()
    items = classify(findings, all_decisions)
    (args.out_dir / "queue.json").write_text(json.dumps({
        "product": product, "snapshot": snap["name"],
        "findings": {"path": str(src), "sha256": sha256_file(src)},
        "decided": len(findings["findings"]) - len(items), "open": items}, indent=2) + "\n",
        encoding="utf-8")

    title = (f"Review queue  |  {args.version}  |  {args.board}  |  "
             f"firmware {product['firmware_sha256'][:12]}")
    table = Table(title=title)
    for col in ("#", "Vulnerability", "Component", "Severity", "Found by", "Cross-check", "State"):
        table.add_column(col, no_wrap=True, justify="right" if col == "#" else "left")
    for n, it in enumerate(items[: max(args.rows, 0)], start=1):
        sev = it["severity"]
        found = "+".join("OSV" if s == "osv-scanner" else "Grype" for s in it["found_by"])
        state = {"stale": "[magenta]stale[/]", "draft": "[yellow]draft[/]"}.get(it["state"], "new")
        table.add_row(str(n), it["id"], it["component"],
                      f"[{SEV_STYLE.get(sev, 'white')}]{sev}[/]", found, it["cross_check"], state)
    console.print(table)
    total = len(findings["findings"])
    by_sev: dict[str, int] = {}
    for it in items:
        by_sev[it["severity"]] = by_sev.get(it["severity"], 0) + 1
    count = {st: sum(1 for it in items if it["state"] == st) for st in ("new", "draft", "stale")}
    console.print(f"{total} findings (snapshot {snap['name']}): {total - len(items)} decided for "
                  f"this firmware, [bold]{len(items)} open[/] ({count['new']} new, "
                  f"{count['draft']} draft, {count['stale']} stale)")
    console.print("open by severity: " + ", ".join(f"{k} {v}" for k, v in by_sev.items()))
    if len(items) > args.rows:
        console.print(f"{len(items) - args.rows} more in {args.out_dir / 'queue.json'} "
                      f"(make queue ROWS={len(items)} shows all)")
    drafts = [it for it in items if it["state"] == "draft"]
    for it in drafts[:3]:
        console.print(f"[yellow]draft {it['id']}:[/] {escape(it['draft_errors'][0] if it['draft_errors'] else '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
