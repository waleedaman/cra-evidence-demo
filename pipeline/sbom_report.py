# SPDX-License-Identifier: Apache-2.0
"""Summarize the SPDX documents written by `west spdx` for one build.

  python -m pipeline.sbom_report --sbom-dir out/v1.0/<board>/sbom --build-dir /ws/build/v1.0/<board>

Prints two short tables (documents; components and their identifiers) plus the
gaps we know about, and writes the same data to <sbom-dir>/summary.json.

This is a deliberately small tag-value reader for reporting only. Validation of
the documents is done with spdx-tools (pyspdxtools) in Phase 4.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from rich.markup import escape
from rich.table import Table

from pipeline.common import console, sha256_file

PURPOSE = {
    "app": "app source files in the build",
    "zephyr": "Zephyr + module source files in the build",
    "build": "libraries + zephyr.elf, linked to sources",
    "modules-deps": "module CPE/PURL (from module.yml)",
    "sdk": "SDK/toolchain headers used",
}
DOC_ORDER = ("app", "zephyr", "build", "modules-deps", "sdk")


@dataclass
class Package:
    name: str = ""
    spdx_id: str = ""
    version: str = ""
    supplier: str = ""
    license: str = ""
    cpe: list[str] = field(default_factory=list)
    purl: list[str] = field(default_factory=list)


@dataclass
class Document:
    name: str
    describes: list[str] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    files: int = 0
    relationships: int = 0
    elf_sha256: str = ""


def read_tag_value(path: Path) -> Document:
    """Read packages, file count and relationships from an SPDX 2.x tag-value file."""
    doc = Document(name=path.stem)
    current: Package | None = None
    in_text = False
    last_file = ""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if in_text:
            in_text = "</text>" not in raw
            continue
        if "<text>" in raw and "</text>" not in raw:
            in_text = True
        key, sep, value = raw.partition(": ")
        if not sep:
            continue
        value = value.strip()
        if key == "PackageName":
            current = Package(name=value)
            doc.packages.append(current)
        elif key == "FileName":
            current = None
            doc.files += 1
            last_file = value
        elif key == "FileChecksum" and last_file.endswith("/zephyr.elf") and value.startswith("SHA256:"):
            doc.elf_sha256 = value.split(":", 1)[1].strip()
        elif key == "Relationship":
            doc.relationships += 1
            parts = value.split()
            if len(parts) == 3 and parts[0] == "SPDXRef-DOCUMENT" and parts[1] == "DESCRIBES":
                doc.describes.append(parts[2])
        elif current is not None:
            if key == "SPDXID":
                current.spdx_id = value
            elif key == "PackageVersion":
                current.version = value
            elif key == "PackageSupplier":
                current.supplier = value
            elif key == "PackageLicenseConcluded":
                current.license = value
            elif key == "ExternalRef":
                ref = value.split()
                if len(ref) == 3 and ref[1] == "cpe23Type":
                    current.cpe.append(ref[2])
                elif len(ref) == 3 and ref[1] == "purl":
                    current.purl.append(ref[2])
    return doc


def stem(spdx_id: str) -> str:
    """SPDXRef-mbedtls-sources / SPDXRef-mbedtls-deps -> mbedtls."""
    return re.sub(r"-(sources|deps)$", "", spdx_id.removeprefix("SPDXRef-"))


def linked_toolchain_archives(map_file: Path) -> list[str]:
    """Static archives linked from outside the build directory (e.g. SDK libc.a)."""
    if not map_file.exists():
        return []
    found: set[str] = set()
    pattern = re.compile(r"(?:^|\s)(/\S+/(lib[\w+-]+\.a))\(")
    build_root = str(map_file.parent.parent)
    for line in map_file.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pattern.search(line)
        if m and not m.group(1).startswith(build_root):
            found.add(m.group(2))
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sbom-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    docs = {p.stem: read_tag_value(p) for p in sorted(args.sbom_dir.glob("*.spdx"))}
    if not docs:
        console.print(f"[bold red]no .spdx files in {args.sbom_dir}[/]")
        return 1

    t1 = Table(title="SPDX 2.3 documents (west spdx)")
    for col in ("Document", "Pkgs", "Files", "Contains"):
        t1.add_column(col, justify="right" if col in ("Pkgs", "Files") else "left")
    for name in [d for d in DOC_ORDER if d in docs] + sorted(set(docs) - set(DOC_ORDER)):
        d = docs[name]
        t1.add_row(f"{name}.spdx", str(len(d.packages)), str(d.files), PURPOSE.get(name, "-"))
    console.print(t1)

    # Components: source packages (zephyr.spdx, app.spdx, sdk.spdx) joined with
    # identifiers from modules-deps.spdx by SPDX ID stem.
    deps = {stem(p.spdx_id): p for p in docs.get("modules-deps", Document("x")).packages}
    rows: list[dict[str, object]] = []
    for doc_name in ("zephyr", "app", "sdk"):
        for p in docs.get(doc_name, Document("x")).packages:
            key = stem(p.spdx_id)
            dep = deps.get(key)
            cpe = sorted(set(p.cpe + (dep.cpe if dep else [])))
            purl = sorted(set(p.purl + (dep.purl if dep else [])))
            version = (dep.version if dep and dep.version else p.version) or "-"
            rows.append({"component": key, "version": version, "cpe": cpe, "purl": purl,
                         "source_document": doc_name, "license": p.license})

    t2 = Table(title="Components and identifiers")
    for col in ("Component", "Version", "CPE", "PURL"):
        t2.add_column(col)
    for r in rows:
        version = str(r["version"])
        version = version[:12] if re.fullmatch(r"[0-9a-f]{40}", version) else version
        t2.add_row(str(r["component"]), version,
                   "[green]yes[/]" if r["cpe"] else "[red]missing[/]",
                   "[green]yes[/]" if r["purl"] else "[red]missing[/]")
    console.print(t2)

    elf_out = args.sbom_dir.parent / "zephyr.elf"
    elf_sbom = docs.get("build", Document("x")).elf_sha256
    elf_ok = bool(elf_sbom) and elf_out.exists() and sha256_file(elf_out) == elf_sbom
    archives = linked_toolchain_archives(args.build_dir / "zephyr" / "zephyr.map")
    console.print(f"zephyr.elf sha256 in build.spdx: {elf_sbom[:16] or '-'}... "
                  f"{'[green]matches out/ artifact[/]' if elf_ok else '[red]no match with out/ artifact[/]'}")
    if archives:
        console.print("Linked from the toolchain, no component in the SBOM: "
                      + escape(", ".join(archives)))
    config = args.build_dir / "zephyr" / ".config"
    host_libc = config.exists() and "CONFIG_EXTERNAL_LIBC=y" in config.read_text(encoding="utf-8")
    if host_libc:
        console.print("Host C library (CONFIG_EXTERNAL_LIBC, dynamically linked): no component in the SBOM")

    summary = {
        "documents": {k: {"describes": v.describes, "packages": [asdict(p) for p in v.packages],
                          "files": v.files, "relationships": v.relationships}
                      for k, v in docs.items()},
        "components": rows,
        "elf_sha256_in_build_spdx": elf_sbom,
        "elf_matches_artifact": elf_ok,
        "toolchain_archives_not_described": archives,
        "host_libc_not_described": host_libc,
    }
    (args.sbom_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n",
                                               encoding="utf-8")
    return 0 if elf_ok else 1


if __name__ == "__main__":
    sys.exit(main())
