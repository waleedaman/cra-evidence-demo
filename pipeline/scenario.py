# SPDX-License-Identifier: Apache-2.0
"""Helpers for the talk scenarios (scenarios/*/run.sh). Never changes tracked files.

  python -m pipeline.scenario setup N --releases v1.0[,v1.1] --board <board>
  python -m pipeline.scenario check --board <board>
  python -m pipeline.scenario show-map --map <file> --id cjson
  python -m pipeline.scenario show-finding --out-dir <dir> --vuln <id>
  python -m pipeline.scenario show-decision --file <decision.yaml>
  python -m pipeline.scenario show-vex --out-dir <dir> --vuln <id>
  python -m pipeline.scenario show-file --path <file> [--start N --end M]
  python -m pipeline.scenario triage --out-dir <dir> --board <board> --version v1.0 [--days 14]

Each scenario works on a copy of the release outputs and of decisions/ under
out/scenarios/<N>/ (Makefile OUT_ROOT=, DECISIONS=, MAP=), so it can be run again and
again; `make reset` deletes out/scenarios/.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.syntax import Syntax
from rich.table import Table

from pipeline import decisions
from pipeline.common import REPO, console

SCEN_ROOT = REPO / "out" / "scenarios"
MAP_FILE = REPO / "identifiers" / "component-map.yaml"
NEEDED = ("artifacts.json", "config", "zephyr.elf", "sbom/zephyr.spdx", "provenance.sigstore.json",
          "normalized/firmware.spdx.json", "findings.json")


def syntax(text: str, lexer: str) -> None:
    console.print(Syntax(text, lexer, theme="ansi_dark", word_wrap=False, background_color="default"))


def cmd_setup(n: str, releases: list[str], board: str) -> int:
    dest = SCEN_ROOT / n
    if dest.exists():
        shutil.rmtree(dest)
    bd = decisions.board_dir(board)
    for rel in releases:
        src = REPO / "out" / rel / bd
        missing = [x for x in NEEDED if not (src / x).exists()]
        if missing:
            console.print(f"[bold red]{src.relative_to(REPO)}: missing {', '.join(missing)}. "
                          "Run make prepare first.[/]")
            return 1
        shutil.copytree(src, dest / rel / bd, ignore=shutil.ignore_patterns("repro"), symlinks=True)
    if (REPO / "decisions").exists():
        shutil.copytree(REPO / "decisions", dest / "decisions")
    else:
        (dest / "decisions").mkdir(parents=True)
    if n == "1":
        # before cJSON was identified there were no cJSON findings, so no cJSON decisions
        for f in (dest / "decisions").rglob("*--cjson.yaml"):
            f.unlink()
        # "before": the reviewed map without the cJSON entry (what the SBOM looked like
        # before anybody noticed the vendored library)
        cmap: dict[str, Any] = yaml.safe_load(MAP_FILE.read_text(encoding="utf-8"))
        cmap["components"] = [c for c in cmap["components"] if c["id"] != "cjson"]
        (dest / "map-before.yaml").write_text(
            "# Scenario 1: identifiers/component-map.yaml WITHOUT the cjson entry\n"
            + yaml.safe_dump(cmap, sort_keys=False, allow_unicode=True), encoding="utf-8")
    console.print(f"scenario {n}: workspace {dest.relative_to(REPO)}/ "
                  f"({', '.join(releases)}, decisions copied)")
    return 0


def cmd_check(board: str) -> int:
    """Is everything the five scenarios need in place?"""
    bd = decisions.board_dir(board)
    rows: list[tuple[str, bool, str]] = []
    for rel in ("v1.0", "v1.1"):
        src = REPO / "out" / rel / bd
        missing = [x for x in NEEDED if not (src / x).exists()]
        rows.append((f"{rel} release outputs", not missing, ", ".join(missing) or "complete"))
    gate = REPO / "out" / "v1.0" / bd / "gate.json"
    result = json.loads(gate.read_text(encoding="utf-8"))["result"] if gate.exists() else "not run"
    rows.append(("v1.0 gate PASS (scenario 5 starts from it)", result == "PASS", result))
    test = REPO / "out" / "evidence" / "cjson-CVE-2024-31755-test.txt"
    rows.append(("cJSON patch test transcript (scenario 2)", test.exists(), "make cjson-test"))
    snaps = yaml.safe_load((REPO / "vulndb" / "snapshots.yaml").read_text(encoding="utf-8"))
    after = "after" in snaps.get("grype", {})
    rows.append(("snapshot 'after' (scenario 5)", True,
                 "recorded" if after else "not recorded: scenario 5 uses the SYNTHETIC record"))
    reviewer = os.environ.get("REVIEWER", "")
    rows.append(("REVIEWER set (scenario 5 signs a triage)", bool(reviewer), reviewer or "REVIEWER=\"<name>\""))
    t = Table(title=f"Scenario readiness  |  {board}")
    t.add_column("Check")
    t.add_column("Result", no_wrap=True)
    t.add_column("Detail")
    for name, ok, detail in rows:
        t.add_row(name, "[bold green]OK[/]" if ok else "[bold red]MISSING[/]", escape(detail))
    console.print(t)
    return 0 if all(ok for _, ok, _ in rows) else 1


def cmd_show_map(path: Path, cid: str) -> int:
    cmap = yaml.safe_load(path.read_text(encoding="utf-8"))
    entry = next((c for c in cmap["components"] if c["id"] == cid), None)
    if entry is None:
        console.print(f"[bold red]no entry {cid} in {path}[/]")
        return 1
    shown = {k: v for k, v in entry.items() if k not in ("comment", "rationale")}
    console.print(f"[bold]{path.relative_to(REPO) if path.is_absolute() else path}[/], entry '{cid}':")
    syntax(yaml.safe_dump([shown], sort_keys=False, allow_unicode=True, width=80), "yaml")
    return 0


def load_findings(out_dir: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out_dir / "findings.json").read_text(encoding="utf-8"))
    return data


def cmd_show_finding(out_dir: Path, vuln: str) -> int:
    f = load_findings(out_dir)
    hits = [x for x in f["findings"] if vuln in {x["id"], *x.get("aliases", [])}]
    if not hits:
        console.print(f"[bold]{vuln}: no finding[/] in {out_dir.relative_to(REPO)}/findings.json "
                      f"(snapshot {f['snapshot']['name']})")
        return 0
    for x in hits:
        t = Table(title=f"Finding {x['id']}  |  {f['product']['release']}  |  snapshot {f['snapshot']['name']}")
        t.add_column("Field", no_wrap=True, style="bold")
        t.add_column("Value")
        t.add_row("component", f"{x['component']} {x['component_version']}")
        t.add_row("severity", f"{x['severity']} ({x.get('score')})")
        t.add_row("found by", ", ".join(x["found_by"]))
        g = x.get("grype") or {}
        if g:
            t.add_row("Grype match", escape(f"{', '.join(g.get('matched_cpes', []))[:70]}"))
            t.add_row("NVD range", escape(str(g.get("version_constraint"))))
        if x.get("osv"):
            t.add_row("OSV match", escape(f"{x['osv']['repo']} @ {x['osv']['version']}"))
        if x.get("osv_view"):
            t.add_row("OSV view", escape(x["osv_view"]))
        t.add_row("summary", escape(x.get("summary", "")[:160]))
        console.print(t)
    return 0


def shorten(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def cmd_show_decision(path: Path) -> int:
    if not path.exists():
        console.print(f"[bold red]{path}: no decision file[/]")
        return 1
    d = decisions.load(path)
    data = {k: v for k, v in d.data.items() if k not in ("finding", "product", "aliases")}
    data["evidence"] = [{e["type"]: shorten(re.sub(r" *[(]make [^)]*[)]", "", str(e["description"])), 110)}
                        for e in data.get("evidence", []) if e["type"] not in ("advisory", "scanner-report")]
    data = {k: v for k, v in data.items() if v not in (None, "", [])}
    data["bound_to"] = f"{d.get('product', 'version')} firmware {str(d.get('product', 'firmware_sha256'))[:12]}"
    console.print(f"[bold]{d.rel}[/]  ({'valid' if d.valid else '[red]draft: ' + escape(d.todo) + '[/]'})")
    syntax(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=80), "yaml")
    return 0


def cmd_show_vex(out_dir: Path, vuln: str) -> int:
    path = out_dir / "vex" / "firmware.openvex.json"
    if not path.exists():
        console.print(f"[bold red]{path.relative_to(REPO)} missing: make vex[/]")
        return 1
    vex = json.loads(path.read_text(encoding="utf-8"))
    stmts = [s for s in vex["statements"] if s["vulnerability"]["name"] == vuln]
    for st in stmts:
        shown = dict(st)
        note = str(shown.pop("status_notes", ""))
        if note:
            shown["status_notes"] = note[:120] + "..."
        console.print(f"[bold]{path.relative_to(REPO)}[/]  (statement for {vuln}; status note shortened)")
        syntax(json.dumps(shown, indent=2), "json")
    if not stmts:
        console.print(f"no statement for {vuln} in {path.relative_to(REPO)}")
    return 0


def cmd_show_file(path: Path, start: int, end: int) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    lexer = {".patch": "diff", ".diff": "diff", ".yaml": "yaml", ".json": "json", ".c": "c",
             ".conf": "ini"}.get(path.suffix, "text")
    console.print(f"[bold]{path.relative_to(REPO) if path.is_absolute() else path}[/]"
                  + (f"  (lines {start}-{end})" if end else ""))
    syntax("\n".join(lines[start - 1:end or None]), lexer)
    return 0


def cmd_triage(out_dir: Path, board: str, version: str, days: int, vuln: str) -> int:
    """Scenario 5: the person on stage opens an investigation for the first new finding."""
    from pipeline.decide import render
    from pipeline.queue import classify
    from pipeline.review import reviewer_ok
    reviewer = os.environ.get("REVIEWER", "")
    if not reviewer_ok(reviewer):
        console.print("[bold red]set REVIEWER=\"<your name>\": the investigation is opened by a person[/]")
        return 2
    f = load_findings(out_dir)
    new = [it for it in classify(f, decisions.load_all()) if it["state"] == "new"
           and (not vuln or it["id"] == vuln)]
    if not new:
        console.print("no new finding to triage")
        return 1
    it = new[0]
    finding = next(x for x in f["findings"] if x["id"] == it["id"] and x["component"] == it["component"])
    today = date.fromisoformat(os.environ["GATE_DATE"]) if os.environ.get("GATE_DATE") else datetime.now(UTC).date()
    due = (today + timedelta(days=days)).isoformat()
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = render(finding, f, version, board, str((out_dir / "findings.json").relative_to(REPO)))
    analysis = (f"  - type: analysis\n    path_or_url: {json.dumps(str((out_dir / 'normalized' / 'firmware.spdx.json').relative_to(REPO)))}\n"
                f"    description: {json.dumps(f'{finding['component']} {finding['component_version']} is a component of this firmware (normalized SBOM); impact on this product not yet analysed')}")
    text = text.replace("\n# The person responsible", "\n" + analysis + "\n# The person responsible", 1)
    text = text.replace("due_date: null", f'due_date: "{due}"')
    text = re.sub(r'^reviewer: .*$', f"reviewer: {json.dumps(reviewer)}", text, count=1, flags=re.M)
    text = re.sub(r'^decided_at: .*$', f'decided_at: "{now}"', text, count=1, flags=re.M)
    text = re.sub(r'^reassess_trigger: .*$', 'reassess_trigger: "investigation result, or the due date"',
                  text, count=1, flags=re.M)
    path = decisions.file_for(version, board, finding["id"], finding["component"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    d = decisions.load(path)
    console.print(f"{'[green]' if d.valid else '[red]'}{d.rel}: under_investigation, due {due}, "
                  f"opened by {escape(reviewer)}[/]")
    return 0 if d.valid else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("setup")
    p.add_argument("n")
    p.add_argument("--releases", default="v1.0")
    p.add_argument("--board", required=True)
    p = sub.add_parser("check")
    p.add_argument("--board", required=True)
    p = sub.add_parser("show-map")
    p.add_argument("--map", type=Path, default=MAP_FILE)
    p.add_argument("--id", required=True)
    p = sub.add_parser("show-finding")
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--vuln", required=True)
    p = sub.add_parser("show-decision")
    p.add_argument("--file", type=Path, required=True)
    p = sub.add_parser("show-vex")
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--vuln", required=True)
    p = sub.add_parser("show-file")
    p.add_argument("--path", type=Path, required=True)
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--end", type=int, default=0)
    p = sub.add_parser("triage")
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--board", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--days", type=int, default=14)
    p.add_argument("--vuln", default="")
    a = parser.parse_args(argv)
    for key in ("out_dir", "file", "path", "map"):
        value = getattr(a, key, None)
        if isinstance(value, Path) and not value.is_absolute():
            setattr(a, key, REPO / value)
    if a.cmd == "setup":
        return cmd_setup(a.n, a.releases.split(","), a.board)
    if a.cmd == "check":
        return cmd_check(a.board)
    if a.cmd == "show-map":
        return cmd_show_map(a.map, a.id)
    if a.cmd == "show-finding":
        return cmd_show_finding(a.out_dir, a.vuln)
    if a.cmd == "show-decision":
        return cmd_show_decision(a.file)
    if a.cmd == "show-vex":
        return cmd_show_vex(a.out_dir, a.vuln)
    if a.cmd == "show-file":
        return cmd_show_file(a.path, a.start, a.end)
    return cmd_triage(a.out_dir, a.board, a.version, a.days, a.vuln)


if __name__ == "__main__":
    sys.exit(main())
