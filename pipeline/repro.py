# SPDX-License-Identifier: Apache-2.0
"""Compare the artifacts of two independent builds (and optionally the release build).

  python -m pipeline.repro --a out/v1.0/<board>/repro/a --b out/v1.0/<board>/repro/b
                           [--release out/v1.0/<board>] --report out/.../repro/report.json

Exit code 1 if build A and build B differ in any artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.table import Table

from pipeline.common import console


def digests(directory: Path) -> dict[str, str]:
    f = directory / "artifacts.json"
    if not f.exists():
        return {}
    data = json.loads(f.read_text(encoding="utf-8"))
    return {name: str(v["sha256"]) for name, v in data["artifacts"].items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", type=Path, required=True)
    parser.add_argument("--b", type=Path, required=True)
    parser.add_argument("--release", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)

    a, b = digests(args.a), digests(args.b)
    rel = digests(args.release) if args.release else {}
    if not a or not b:
        console.print("[bold red]missing artifacts.json for build A or B[/]")
        return 1

    table = Table(title="Reproducibility: two clean builds, different build paths")
    for col in ("Artifact", "Build A", "Build B", "A = B", "Release (out/)"):
        table.add_column(col)
    rows = []
    for name in sorted(set(a) | set(b)):
        same = name in a and name in b and a[name] == b[name]
        rel_state = "-" if name not in rel else ("same" if rel[name] == a.get(name) else "differs")
        rows.append({"artifact": name, "a": a.get(name), "b": b.get(name), "identical": same,
                     "release": rel.get(name), "release_state": rel_state})
        table.add_row(name, (a.get(name) or "-")[:12], (b.get(name) or "-")[:12],
                      "[bold green]identical[/]" if same else "[bold red]DIFFERENT[/]",
                      {"same": "[green]same[/]", "differs": "[yellow]differs[/]"}.get(rel_state, "-"))
    console.print(table)
    ok = all(r["identical"] for r in rows)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"result": "PASS" if ok else "FAIL", "artifacts": rows},
                                      indent=2) + "\n", encoding="utf-8")
    if any(r["release_state"] == "differs" for r in rows):
        console.print("[yellow]out/ release build differs: it was built from other inputs "
                      "(older commit, other certs or image). Rebuild it with make build.[/]")
    console.print("[bold green]REPRODUCIBLE[/]" if ok else "[bold red]NOT REPRODUCIBLE[/] "
                  "(see docs/reproducibility.md)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
