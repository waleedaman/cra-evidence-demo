# SPDX-License-Identifier: Apache-2.0
"""What changed between two releases of the same board, and which decisions it breaks.

  python -m pipeline.diff --out-root out --board <board> --a v1.0 --b v1.1

Compares the files both builds produced: firmware hash, Kconfig (.config), the source
files compiled into the image (build SBOM), component versions (normalized SBOM) and
findings. Then checks every decision of release A: is it bound to B's firmware (never,
after a rebuild) and does its reassess_trigger hold in B's .config.
Writes out/<b>/<board>/diff-<a>.json.
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
from pipeline.common import REPO, console
from pipeline.decide import config_values, triggers_hit
from pipeline.evidence_compiled import spdx_files


def sources(out_dir: Path) -> set[str]:
    """C/assembly source files listed in the build SBOM (zephyr + app documents)."""
    files: set[str] = set()
    for doc in ("zephyr", "app"):
        for name in spdx_files(out_dir / "sbom" / f"{doc}.spdx"):
            if name.endswith((".c", ".S", ".s", ".cpp")):
                files.add(f"{doc}:{name.removeprefix('./')}")
    return files


def components(out_dir: Path) -> dict[str, str]:
    path = out_dir / "normalized" / "firmware.spdx.json"
    if not path.exists():
        return {}
    sbom = json.loads(path.read_text(encoding="utf-8"))
    return {p["name"]: p.get("versionInfo", "") for p in sbom["packages"]}


def finding_keys(out_dir: Path) -> set[tuple[str, str]] | None:
    path = out_dir / "findings.json"
    if not path.exists():
        return None
    return {(f["id"], f["component"]) for f in json.loads(path.read_text(encoding="utf-8"))["findings"]}


def compare(out_root: Path, board: str, a: str, b: str) -> dict[str, Any]:
    da, db = (out_root / r / decisions.board_dir(board) for r in (a, b))
    art_a, art_b = (json.loads((d / "artifacts.json").read_text(encoding="utf-8")) for d in (da, db))
    fw = next(n for n in ("zephyr.uf2", "zephyr.exe", "zephyr.bin") if n in art_a["artifacts"])
    ca, cb = config_values(da / "config"), config_values(db / "config")
    kconfig = {k: [ca.get(k, "n"), cb.get(k, "n")] for k in sorted(set(ca) | set(cb))
               if ca.get(k, "n") != cb.get(k, "n")}
    sa, sb = sources(da), sources(db)
    comp_a, comp_b = components(da), components(db)
    comp_changes = {k: [comp_a.get(k, "-"), comp_b.get(k, "-")] for k in sorted(set(comp_a) | set(comp_b))
                    if comp_a.get(k) != comp_b.get(k)}
    fa, fb = finding_keys(da), finding_keys(db)
    sha_b = art_b["artifacts"][fw]["sha256"]
    dec = []
    for d in decisions.load_all(decisions.DECISIONS_DIR / a / decisions.board_dir(board)):
        hits = triggers_hit(str(d.get("reassess_trigger") or ""), cb)
        dec.append({"file": d.rel, "vuln_id": d.get("vuln_id"), "component": d.get("component"),
                    "status": d.get("status"), "trigger": d.get("reassess_trigger"),
                    "trigger_holds_in_b": hits,
                    "bound_to_b": d.get("product", "firmware_sha256") == sha_b})
    return {
        "a": a, "b": b, "board": board, "firmware_file": fw,
        "firmware_sha256": [art_a["artifacts"][fw]["sha256"], sha_b],
        "kconfig_changed": kconfig,
        "sources_added": sorted(sb - sa), "sources_removed": sorted(sa - sb),
        "components_changed": comp_changes,
        "findings": None if fa is None or fb is None else {
            "a": len(fa), "b": len(fb), "added": sorted(map(list, fb - fa)),
            "removed": sorted(map(list, fa - fb))},
        "decisions_of_a": dec,
    }


def render(r: dict[str, Any]) -> None:
    a, b = r["a"], r["b"]
    t = Table(title=f"make diff  |  {a} -> {b}  |  {r['board']}")
    t.add_column("What", no_wrap=True)
    t.add_column(a)
    t.add_column(b)
    t.add_column("Change")
    sha = r["firmware_sha256"]
    t.add_row(f"firmware ({r['firmware_file']})", sha[0][:12], sha[1][:12],
              "[yellow]rebuilt[/]" if sha[0] != sha[1] else "same")
    for name, (va, vb) in list(r["components_changed"].items())[:4]:
        t.add_row(f"component {name}", va, vb, "[yellow]version[/]")
    kc = r["kconfig_changed"]
    net = sorted(kc, key=lambda k: (k != "CONFIG_NET_IPV6", "LOG_LEVEL" in k,
                                    not k.startswith("CONFIG_NET_"), k))
    for k in net[:4]:
        t.add_row(k, kc[k][0], kc[k][1], "[yellow]Kconfig[/]")
    t.add_row("Kconfig options changed", "", "", f"[yellow]{len(kc)}[/]" if kc else "0")
    t.add_row("source files compiled", "", "",
              f"[yellow]+{len(r['sources_added'])} / -{len(r['sources_removed'])}[/]")
    fnd = r["findings"]
    if fnd is not None:
        same = not fnd["added"] and not fnd["removed"]
        t.add_row("scanner findings", str(fnd["a"]), str(fnd["b"]),
                  "[bold]identical[/]" if same else f"+{len(fnd['added'])} / -{len(fnd['removed'])}")
    dec = r["decisions_of_a"]
    t.add_row(f"decisions of {a} bound to {b}", "", "",
              f"[bold red]{sum(d['bound_to_b'] for d in dec)} of {len(dec)}[/]")
    console.print(t)
    added = [s.split(":", 1)[1] for s in r["sources_added"] if s.startswith("zephyr:")]
    if added:
        console.print(f"newly compiled ({len(added)}): " + escape(", ".join(
            Path(s).name for s in added[:10])) + (" ..." if len(added) > 10 else ""))
    hit = [d for d in dec if d["trigger_holds_in_b"]]
    if hit:
        ht = Table(title=f"Decisions of {a} whose reassess trigger holds in {b}")
        ht.add_column("Vulnerability", no_wrap=True)
        ht.add_column("Component")
        ht.add_column(f"Status in {a}")
        ht.add_column("Trigger now true", style="bold red")
        for d in hit[:8]:
            ht.add_row(str(d["vuln_id"]), str(d["component"]), str(d["status"]),
                       ", ".join(d["trigger_holds_in_b"]))
        console.print(ht)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-root", type=Path, default=Path("out"))
    parser.add_argument("--board", required=True)
    parser.add_argument("--a", required=True)
    parser.add_argument("--b", required=True)
    args = parser.parse_args(argv)
    root = args.out_root if args.out_root.is_absolute() else REPO / args.out_root
    for rel in (args.a, args.b):
        if not (root / rel / decisions.board_dir(args.board) / "artifacts.json").exists():
            console.print(f"[bold red]no build of {rel} for {args.board} under {args.out_root}[/]")
            return 1
    report = compare(root, args.board, args.a, args.b)
    dest = root / args.b / decisions.board_dir(args.board) / f"diff-{args.a}.json"
    dest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    render(report)
    console.print(f"full list -> {dest.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
