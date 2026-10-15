# SPDX-License-Identifier: Apache-2.0
"""Review queue: findings without a human decision for THIS release and firmware hash.

  python -m pipeline.queue --out-dir out/v1.0/<board> --board <board> --version v1.0 [--rows 15]

Reads out/<v>/<board>/findings.json (make scan) and every decision file under
decisions/ (YAML; the data model and its schema come in Phase 6). A finding counts as
decided only if a decision has the same vulnerability ID (or alias), the same component
PURL (component name when the component has no PURL), and product.version and
product.firmware_sha256 equal to this build. A decision for another version or another
firmware hash is reported as "stale": it may be a good starting point, but it does not
cover this firmware.

Writes the full list to out/<v>/<board>/queue.json and prints the first --rows entries.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.table import Table

from pipeline.common import REPO, console, sha256_file

DECISIONS_DIR = REPO / "decisions"
SEV_STYLE = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "cyan"}


@dataclass
class Decision:
    path: Path
    vuln_id: str
    component_purl: str | None
    component: str | None
    version: str
    firmware_sha256: str
    status: str


def load_decisions(root: Path = DECISIONS_DIR) -> tuple[list[Decision], list[str]]:
    decisions: list[Decision] = []
    problems: list[str] = []
    if not root.exists():
        return decisions, problems
    for path in sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")]):
        rel = path.relative_to(REPO)
        try:
            d: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
            product = d["product"]
            decisions.append(Decision(path, str(d["vuln_id"]), d.get("component_purl"),
                                      d.get("component"), str(product["version"]),
                                      str(product["firmware_sha256"]), str(d.get("status", ""))))
        except (yaml.YAMLError, KeyError, TypeError) as exc:
            problems.append(f"{rel}: not a usable decision ({type(exc).__name__})")
    return decisions, problems


def same_component(d: Decision, f: dict[str, Any]) -> bool:
    if f.get("component_purl"):
        return bool(d.component_purl == f["component_purl"])
    return bool(d.component == f["component"])


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


def classify(findings: dict[str, Any], decisions: list[Decision]) -> list[dict[str, Any]]:
    product = findings["product"]
    items: list[dict[str, Any]] = []
    for f in findings["findings"]:
        ids = {f["id"], *f.get("aliases", [])}
        matching = [d for d in decisions if d.vuln_id in ids and same_component(d, f)]
        current = [d for d in matching if d.version == product["version"]
                   and d.firmware_sha256 == product["firmware_sha256"]]
        if current:
            continue
        state = "stale" if matching else "new"
        items.append({
            "id": f["id"], "component": f["component"], "component_purl": f.get("component_purl"),
            "severity": f["severity"], "found_by": f["found_by"], "cross_check": cross_check(f),
            "state": state,
            "stale_decisions": [{"file": str(d.path.relative_to(REPO)), "version": d.version,
                                 "firmware_sha256": d.firmware_sha256, "status": d.status}
                                for d in matching],
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
    decisions, problems = load_decisions()
    items = classify(findings, decisions)
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
        state = "[magenta]stale[/]" if it["state"] == "stale" else "new"
        table.add_row(str(n), it["id"], it["component"],
                      f"[{SEV_STYLE.get(sev, 'white')}]{sev}[/]", found, it["cross_check"], state)
    console.print(table)
    total = len(findings["findings"])
    by_sev: dict[str, int] = {}
    for it in items:
        by_sev[it["severity"]] = by_sev.get(it["severity"], 0) + 1
    stale = sum(1 for it in items if it["state"] == "stale")
    console.print(f"{total} findings (snapshot {snap['name']}): {total - len(items)} decided for "
                  f"this firmware, [bold]{len(items)} open[/] ({len(items) - stale} new, {stale} stale)")
    console.print("open by severity: " + ", ".join(f"{k} {v}" for k, v in by_sev.items()))
    if len(items) > args.rows:
        console.print(f"{len(items) - args.rows} more in {args.out_dir / 'queue.json'} "
                      f"(make queue ROWS={len(items)} shows all)")
    for p in problems:
        console.print(f"[yellow]{escape(p)}[/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
