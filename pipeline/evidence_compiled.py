# SPDX-License-Identifier: Apache-2.0
"""Is a source file (and a function) really part of this firmware? Evidence from the build.

  python -m pipeline.evidence_compiled --out-dir out/v1.0/<board> --file subsys/net/ip/icmpv6.c \
      [--symbol icmpv6_handle_echo_request] [--kconfig CONFIG_NET_IPV6]

Four independent checks, all from files the build produced:
  1. build SBOM  (west spdx): is the file listed as a source of the build (zephyr.spdx /
                 app.spdx), and is it GENERATED_FROM into a library or the image (build.spdx)?
  2. .config     : value of the Kconfig options that control the feature
  3. linker map  : bytes of code (.text) that the file's object contributes to zephyr.elf
  4. symbols     : are the named functions present in zephyr.elf (nm)?

"Compiled" is not the same as "contains code": a file can be compiled and still contribute
nothing (#ifdef, unused functions removed by --gc-sections). That is why all four are shown.
Writes out/<v>/<board>/evidence/<file>.json for use as decision evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from rich.table import Table

from pipeline.common import console, run, sha256_file

SDK_NM = "gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-nm"


def spdx_files(path: Path) -> dict[str, str]:
    """FileName -> SPDXID of a tag-value document (plain text scan, no full parse needed)."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    name = ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("FileName: "):
            name = line[10:].strip()
        elif line.startswith("SPDXID: SPDXRef-File") and name:
            out[name] = line[8:].strip()
            name = ""
    return out


def find_in_sbom(sbom: Path, rel: str) -> list[tuple[str, str, str]]:
    """(document, file name, SPDX ID) for every listed file whose path ends with rel."""
    hits = []
    for doc in ("zephyr", "app"):
        for fname, sid in spdx_files(sbom / f"{doc}.spdx").items():
            if fname.endswith("/" + rel) or fname == "./" + rel:
                hits.append((doc, fname, sid))
    return hits


def generated_into(build_spdx: Path, doc: str, sid: str) -> list[str]:
    """Build outputs (libraries, zephyr.elf) that build.spdx says are GENERATED_FROM the file."""
    if not build_spdx.exists():
        return []
    files = {v: k for k, v in spdx_files(build_spdx).items()}
    pat = re.compile(rf"^Relationship: (\S+) GENERATED_FROM DocumentRef-{doc}:{re.escape(sid)}$", re.M)
    return sorted({Path(files.get(m.group(1), m.group(1))).name
                   for m in pat.finditer(build_spdx.read_text(encoding="utf-8", errors="replace"))})


def map_text_bytes(map_file: Path, rel: str) -> tuple[int, int]:
    """(bytes in .text sections, number of input sections) from the object built from rel."""
    if not map_file.exists():
        return 0, 0
    obj = f"({Path(rel).name}.obj)"
    total = count = 0
    pending = ""
    for line in map_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith(".text") and len(stripped.split()) == 1:
            pending = stripped            # section name alone; address/size on next line
            continue
        parts = stripped.split()
        section = pending or (parts[0] if parts else "")
        pending = ""
        if not section.startswith(".text") or obj not in line:
            continue
        nums = [p for p in parts if p.startswith("0x")]
        if len(nums) >= 2:
            total += int(nums[1], 16)
            count += 1
    return total, count


def elf_symbols(elf: Path, board: str) -> set[str]:
    sdk = os.environ.get("ZEPHYR_SDK_INSTALL_DIR", "/opt/toolchains/zephyr-sdk")
    nm = "nm" if board.startswith("native_sim") else str(Path(sdk) / SDK_NM)
    res = run([nm, "--defined-only", str(elf)])
    return {ln.split()[-1] for ln in res.stdout.splitlines() if len(ln.split()) >= 3}


def kconfig_values(config: Path, names: list[str]) -> dict[str, str]:
    text = config.read_text(encoding="utf-8") if config.exists() else ""
    vals = {}
    for n in names:
        m = re.search(rf"^{re.escape(n)}=(.*)$", text, re.M)
        vals[n] = m.group(1) if m else ("not set" if f"# {n} is not set" in text else "not present")
    return vals


def check(out_dir: Path, rel: str, symbols: list[str], kconfig: list[str]) -> dict[str, Any]:
    meta = json.loads((out_dir / "artifacts.json").read_text(encoding="utf-8"))
    hits = find_in_sbom(out_dir / "sbom", rel)
    into = sorted({lib for doc, _, sid in hits for lib in generated_into(out_dir / "sbom" / "build.spdx", doc, sid)})
    nbytes, nsect = map_text_bytes(out_dir / "zephyr.map", rel)
    syms = elf_symbols(out_dir / "zephyr.elf", meta["board"]) if symbols else set()
    present = {s: s in syms for s in symbols}
    code = bool(into) and nbytes > 0
    if not hits:
        verdict = "not compiled: the file is not a source of this build"
    elif not code and not any(present.values()):
        verdict = "compiled, but contributes no code to zephyr.elf"
    elif symbols and not any(present.values()):
        verdict = "file contributes code, the named functions are not in zephyr.elf"
    else:
        verdict = "present in zephyr.elf"
    return {
        "file": rel, "release": meta["version"], "board": meta["board"],
        "zephyr_elf_sha256": sha256_file(out_dir / "zephyr.elf"),
        "sbom_listed": [f"{doc}.spdx: {name}" for doc, name, _ in hits],
        "generated_into": into, "map_text_bytes": nbytes, "map_text_sections": nsect,
        "symbols": present, "kconfig": kconfig_values(out_dir / "config", kconfig),
        "verdict": verdict,
    }


def render(r: dict[str, Any]) -> None:
    t = Table(title=f"Compiled? {r['file']}  |  {r['release']}  |  {r['board']}")
    t.add_column("Check")
    t.add_column("Result")
    t.add_row("1 build SBOM: listed as source", "; ".join(r["sbom_listed"]) or "[green]no[/]")
    t.add_row("1 build SBOM: compiled into", ", ".join(r["generated_into"]) or "[green]nothing[/]")
    for k, v in r["kconfig"].items():
        t.add_row(f"2 .config: {k}", v)
    t.add_row("3 linker map: .text from this file",
              f"{r['map_text_bytes']} bytes ({r['map_text_sections']} sections)")
    for s, ok in r["symbols"].items():
        t.add_row(f"4 zephyr.elf: {s}()", "[red]present[/]" if ok else "[green]absent[/]")
    console.print(t)
    style = "red" if r["verdict"].startswith("present") else "green"
    console.print(f"[bold {style}]{r['verdict']}[/]   (zephyr.elf {r['zephyr_elf_sha256'][:16]}...)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--file", required=True, help="path relative to the Zephyr or app tree")
    parser.add_argument("--symbol", action="append", default=[])
    parser.add_argument("--kconfig", action="append", default=[])
    args = parser.parse_args(argv)
    if not (args.out_dir / "artifacts.json").exists():
        console.print(f"[bold red]{args.out_dir}: no build (make build)[/]")
        return 1
    syms = [s for arg in args.symbol for s in arg.split(",") if s]
    kc = [k for arg in args.kconfig for k in arg.split(",") if k]
    r = check(args.out_dir, args.file.removeprefix("./"), syms, kc)
    render(r)
    dest = args.out_dir / "evidence" / (args.file.replace("/", "_") + ".json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(r, indent=2) + "\n", encoding="utf-8")
    console.print(f"evidence -> {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
