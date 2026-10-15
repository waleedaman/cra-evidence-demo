# SPDX-License-Identifier: Apache-2.0
"""Validate SBOM documents: SPDX schema (spdx-tools) + minimum-element checks.

  python -m pipeline.validate --out-dir out/v1.0/<board> --board <board> --version v1.0

Checks every out/<v>/<board>/sbom/*.spdx (raw west spdx output) and, once it exists,
out/<v>/<board>/normalized/firmware.spdx.json. Per document:

  SPDX 2.3   spdx-tools 0.8.5 validation (validate_full_spdx_document)
  NTIA       ntia-conformance-checker 6.0.0, compliance "ntia" (2021 NTIA minimum elements)
  FSCT3-min  ntia-conformance-checker 6.0.0, compliance "fsct3-min" (CISA FSCT 2024 minimum)
  CPE/PURL   our own check: packages that carry at least one CPE or PURL. The NTIA
             checker accepts the SPDX ID as "identifier", which no scanner can match.

BSI TR-03183-2 is not run: ntia-conformance-checker 6.0.0 implements its checks only
for SPDX 3 documents (bsi_checker.py), and west spdx writes SPDX 2.x.

Raw JSON reports go to out/<v>/<board>/validate/. Exit code 1 if any document is not
valid SPDX, or if the normalized document fails NTIA. Gaps in the raw documents are
expected and only reported.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ntia_conformance_checker.base_checker import BaseChecker
from ntia_conformance_checker.fsct_checker import FSCT3Checker
from ntia_conformance_checker.ntia_checker import NTIAChecker
from rich.markup import escape
from rich.table import Table
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.error import SPDXParsingError

from pipeline import spdxio
from pipeline.common import console

RAW_ORDER = ("app", "zephyr", "build", "modules-deps", "sdk")
NORMALIZED = Path("normalized") / "firmware.spdx.json"
ID_TYPES = {"cpe22Type", "cpe23Type", "purl"}

# The checker re-parses the file in its constructor. We parse once (with the fast
# licensing workaround) and hand the parsed document to every checker.
_PARSED: dict[str, Document] = {}


class _NTIA(NTIAChecker):
    def parse_file(self) -> Document | None:
        return _PARSED.get(self.file)


class _FSCT3(FSCT3Checker):
    def parse_file(self) -> Document | None:
        return _PARSED.get(self.file)


@dataclass
class Conformance:
    compliant: bool
    failed: list[str] = field(default_factory=list)      # requirement labels
    missing: dict[str, list[str]] = field(default_factory=dict)  # element -> components


@dataclass
class DocResult:
    document: str
    packages: int
    reachable: int
    with_ids: int
    spdx_errors: list[str]
    ntia: Conformance
    fsct3: Conformance


def _conformance(checker: BaseChecker) -> Conformance:
    failed = [label for label, ok in checker.table_elements if not ok]
    missing = {info: [name for name, _ in comps]
               for info, comps in checker.all_components_without_info}
    return Conformance(compliant=bool(checker.compliant), failed=failed, missing=missing)


def check(path: Path, label: str | None = None, report_dir: Path | None = None) -> DocResult:
    """Run all checks on one SPDX document. Optionally write a JSON report per checker."""
    name = label or path.name
    try:
        doc = spdxio.parse(path)
    except SPDXParsingError as exc:
        messages = [str(m) for m in exc.get_messages()]
        failed = Conformance(compliant=False, failed=["document could not be parsed"])
        if report_dir is not None:
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / f"{Path(name).name}.json").write_text(
                json.dumps({"document": name, "parse_errors": messages}, indent=2) + "\n",
                encoding="utf-8")
        return DocResult(document=name, packages=0, reachable=0, with_ids=0,
                         spdx_errors=["parse error: " + m for m in messages],
                         ntia=failed, fsct3=failed)
    _PARSED[str(path)] = doc
    errors = spdxio.validate(doc)
    previous = logging.root.manager.disable
    logging.disable(logging.ERROR)   # the checker logs floating/unknown elements itself
    try:
        ntia = _NTIA(str(path), validate=True, compliance="ntia", sbom_spec="spdx2")
        fsct = _FSCT3(str(path), validate=True, compliance="fsct3-min", sbom_spec="spdx2")
    finally:
        logging.disable(previous)
    reachable = ntia.reachable_component_ids
    with_ids = sum(1 for p in doc.packages if p.spdx_id in reachable
                   and any(r.reference_type in ID_TYPES for r in p.external_references))
    if report_dir is not None:
        report_dir.mkdir(parents=True, exist_ok=True)
        out: dict[str, Any] = {"document": name, "spdx_validation_errors": errors,
                               "ntia": ntia.output_json(), "fsct3-min": fsct.output_json(),
                               "floating_packages": sorted(ntia.floating_component_ids)}
        (report_dir / f"{Path(name).name}.json").write_text(
            json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
    return DocResult(document=name, packages=len(doc.packages), reachable=len(reachable),
                     with_ids=with_ids, spdx_errors=errors, ntia=_conformance(ntia),
                     fsct3=_conformance(fsct))


# Short names for the table; full labels are in the JSON report.
_SHORT = {"name": "name", "version": "version", "supplier": "supplier",
          "identifier": "id", "concluded_license": "license", "copyright_text": "copyright"}
_SHORT_DOC = {"SBOM author name provided?": "author",
              "SBOM creation timestamp provided?": "timestamp",
              "SBOM generation context (SBOM type) provided?": "SBOM type",
              "Dependency relationships provided?": "relationships"}


def _cell(c: Conformance) -> str:
    if c.compliant:
        return "[green]PASS[/]"
    parts = [f"{_SHORT.get(k, k)} {len(v)}" for k, v in c.missing.items() if v]
    parts += [_SHORT_DOC.get(f, f) for f in c.failed if not f.startswith("All component")]
    return "[red]FAIL[/] " + ", ".join(parts)


def ntia_cell(c: Conformance) -> str:
    return _cell(c)


def fsct_cell(c: Conformance, detail: bool = False) -> str:
    if detail or c.compliant:
        return _cell(c)
    return f"[red]FAIL[/] ({len(c.failed)})"


def find_documents(out_dir: Path) -> list[tuple[Path, str]]:
    raw = {p.stem: p for p in (out_dir / "sbom").glob("*.spdx")}
    docs = [(raw[n], f"{n}.spdx") for n in RAW_ORDER if n in raw]
    docs += [(raw[n], f"{n}.spdx") for n in sorted(set(raw) - set(RAW_ORDER))]
    if (out_dir / NORMALIZED).exists():
        docs.append((out_dir / NORMALIZED, str(NORMALIZED)))
    return docs


def render(results: list[DocResult], title: str) -> None:
    table = Table(title=title)
    table.add_column("Document", no_wrap=True)
    table.add_column("Pkgs", justify="right")
    table.add_column("SPDX")
    table.add_column("NTIA minimum elements")
    table.add_column("FSCT3", no_wrap=True)
    table.add_column("CPE/PURL", justify="right")
    for i, r in enumerate(results):
        valid = "[green]valid[/]" if not r.spdx_errors else "[red]INVALID[/]"
        last_raw = i + 1 < len(results) and results[i + 1].document == str(NORMALIZED)
        table.add_row(Path(r.document).name, str(r.reachable), valid, ntia_cell(r.ntia),
                      fsct_cell(r.fsct3), f"{r.with_ids}/{r.reachable}", end_section=last_raw)
    console.print(table)
    for r in results:
        if r.spdx_errors:
            console.print(f"[red]{Path(r.document).name}:[/] {escape(r.spdx_errors[0][:240])}")
        if r.packages > r.reachable:
            console.print(f"{Path(r.document).name}: {r.packages - r.reachable} more packages "
                          "not reachable from the document root (not checked)")
    norm = [r for r in results if r.document == str(NORMALIZED)]
    if norm:
        console.print(f"FSCT3 gaps in firmware.spdx.json: {fsct_cell(norm[0].fsct3, detail=True)}")
    console.print("FSCT3 'SBOM type' exists only in SPDX 3. BSI TR-03183-2: not checked "
                  "(checker supports SPDX 3 only).")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    docs = find_documents(args.out_dir)
    if not docs:
        console.print(f"[bold red]no SPDX documents in {args.out_dir}/sbom; run make sbom[/]")
        return 1
    report_dir = args.out_dir / "validate"
    results = [check(path, label, report_dir) for path, label in docs]
    render(results, f"SBOM checks  |  {args.version}  |  {args.board}")
    (report_dir / "summary.json").write_text(
        json.dumps([asdict(r) for r in results], indent=2) + "\n", encoding="utf-8")

    invalid = [r.document for r in results if r.spdx_errors]
    normalized_fail = [r.document for r in results
                       if r.document == str(NORMALIZED) and not r.ntia.compliant]
    if invalid:
        console.print(f"[bold red]not valid SPDX: {', '.join(invalid)}[/] (all messages: {report_dir})")
    if normalized_fail:
        console.print("[bold red]normalized SBOM fails NTIA minimum elements[/]")
    return 1 if invalid or normalized_fail else 0


if __name__ == "__main__":
    sys.exit(main())
