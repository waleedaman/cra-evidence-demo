# SPDX-License-Identifier: Apache-2.0
"""Merge the raw west spdx documents into one component-level SBOM (SPDX 2.3 JSON).

  python -m pipeline.normalize --out-dir out/v1.0/<board> --board <board> --version v1.0

Input:  out/<v>/<board>/sbom/{app,zephyr,modules-deps,sdk,build}.spdx + summary.json,
        out/<v>/<board>/artifacts.json, app/VERSION,
        identifiers/component-map.yaml (reviewed additions, see that file's header)
Output: out/<v>/<board>/normalized/firmware.spdx.json   the SBOM scanners consume
        out/<v>/<board>/normalized/report.json          what was merged, added, dropped

What it does:
  1. One root package for the firmware (the deployable artifact, with SHA-256 + SHA-512).
  2. One package per source tree that has at least one file in this build, merging the
     file inventory (zephyr.spdx) with the identifiers from modules-deps.spdx.
     Source trees with 0 files in this build are dropped (and reported).
  3. Toolchain components that west spdx does not describe (libc.a, libgcc.a) are added
     only from component-map.yaml entries whose evidence is found in this build.
  4. Map entries add CPE/PURL/supplier; each change is recorded as an SPDX annotation.
     A map entry written for another version stops the run (it needs a new review).
  5. The 94 CMake build targets of build.spdx are not components and are not copied; the
     raw documents stay next to it, referenced by checksum (ExternalDocumentRef).

The output is deterministic: same inputs + same map -> byte-identical file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from rich.markup import escape
from rich.table import Table
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Annotation,
    AnnotationType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    ExternalDocumentRef,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
    PackagePurpose,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
)

from pipeline import spdxio, validate
from pipeline.common import REPO, console, sha256_file

MAP_FILE = REPO / "identifiers" / "component-map.yaml"
MAP_SCHEMA = REPO / "identifiers" / "component-map.schema.json"
APP_VERSION_FILE = REPO / "app" / "VERSION"
TOOL = Actor(ActorType.TOOL, "cra-evidence-demo-normalize-1")
PRIMARY_ARTIFACTS = ("zephyr.uf2", "zephyr.hex", "zephyr.bin", "zephyr.exe", "zephyr.elf")
ID_TYPES = {"cpe22Type", "cpe23Type", "purl"}


class MapError(Exception):
    """component-map.yaml is invalid or does not fit this build."""


@dataclass
class Component:
    id: str
    package: Package
    source: str                                   # where the component came from
    files: int = 0
    added: list[str] = field(default_factory=list)   # what the map changed
    entry: dict[str, Any] | None = None


def spdx_id(name: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def actor(text: str) -> Actor:
    kind, _, name = text.partition(": ")
    return Actor(ActorType[kind.upper()], name)


def ext_ref(locator: str) -> ExternalPackageRef:
    if locator.startswith("cpe:2.3:"):
        return ExternalPackageRef(ExternalPackageRefCategory.SECURITY, "cpe23Type", locator)
    return ExternalPackageRef(ExternalPackageRefCategory.PACKAGE_MANAGER, "purl", locator)


def stem(raw_id: str) -> str:
    """SPDXRef-mbedtls-sources / SPDXRef-mbedtls-deps -> mbedtls (same as sbom_report)."""
    return re.sub(r"-(sources|deps)$", "", raw_id.removeprefix("SPDXRef-"))


def load_map(path: Path = MAP_FILE) -> dict[str, Any]:
    data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema = json.loads(MAP_SCHEMA.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        where = "/".join(str(p) for p in exc.absolute_path) or "(top level)"
        raise MapError(f"{path.name}: {where}: {exc.message}") from exc
    ids = [c["id"] for c in data["components"]]
    if len(ids) != len(set(ids)):
        raise MapError(f"{path.name}: duplicate component ids")
    assert isinstance(data, dict)
    return data


def app_version(release: str = "") -> str:
    """Firmware version: releases/<release>/VERSION if that release exists, else app/VERSION."""
    rel = REPO / "releases" / release / "VERSION"
    path = rel if release and rel.exists() else APP_VERSION_FILE
    fields = dict(re.findall(r"^(\w+)\s*=\s*(\S*)\s*$", path.read_text(encoding="utf-8"), re.M))
    return f"{fields['VERSION_MAJOR']}.{fields['VERSION_MINOR']}.{fields['PATCHLEVEL']}"


def files_per_package(doc: Document) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel in doc.relationships:
        if rel.relationship_type == RelationshipType.CONTAINS:
            counts[rel.spdx_element_id] = counts.get(rel.spdx_element_id, 0) + 1
    return counts


def sha_of(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(path.read_bytes())
    return h.hexdigest()


def annotate(c: Component, entry: dict[str, Any], changes: list[str]) -> Annotation:
    reviewed = bool(entry["reviewed_by"])
    text = (f"identifiers/component-map.yaml entry '{entry['id']}': {'; '.join(changes)}. "
            f"Rationale: {entry['rationale']} Evidence: {entry.get('evidence', 'n/a')} "
            f"Added by {entry['added_by']} on {entry['added_on']}; "
            + (f"reviewed by {entry['reviewed_by']} on {entry['reviewed_on']}." if reviewed
               else "NOT reviewed by a person yet."))
    day = entry["reviewed_on"] if reviewed and entry["reviewed_on"] else entry["added_on"]
    return Annotation(c.package.spdx_id, AnnotationType.REVIEW if reviewed else AnnotationType.OTHER,
                      TOOL, datetime.fromisoformat(f"{day}T00:00:00"), text)


def apply_entry(c: Component, entry: dict[str, Any]) -> list[str]:
    """Apply supplier / CPE / PURL / comment from a map entry. Returns the change list."""
    p = c.package
    changes: list[str] = []
    if "supplier" in entry and (p.supplier is None or str(p.supplier) != entry["supplier"]):
        p.supplier = actor(entry["supplier"])
        changes.append(f"supplier {entry['supplier']}")
    have = {r.locator for r in p.external_references}
    for loc in entry.get("add_cpe", []) + entry.get("add_purl", []):
        if loc not in have:
            p.external_references.append(ext_ref(loc))
            changes.append(f"added {loc}")
    if "comment" in entry:
        p.comment = " ".join(filter(None, [p.comment, entry["comment"].strip()]))
    c.added = changes
    c.entry = entry
    return changes


def build(out_dir: Path, board: str, version: str, cmap: dict[str, Any],
          map_file: Path = MAP_FILE) -> tuple[Document, dict[str, Any]]:
    sbom = out_dir / "sbom"
    raw = {name: spdxio.parse(sbom / f"{name}.spdx")
           for name in ("app", "zephyr", "modules-deps", "sdk", "build")}
    summary = json.loads((sbom / "summary.json").read_text(encoding="utf-8"))
    artifacts = json.loads((out_dir / "artifacts.json").read_text(encoding="utf-8"))["artifacts"]
    linked = set(summary.get("toolchain_archives_not_described", []))
    report: dict[str, Any] = {"dropped": [], "gaps": [], "unreviewed": [], "map_unused": []}

    # -- root package: the firmware as delivered -----------------------------------------
    prod = cmap["product"]
    fw_version = app_version(version)
    primary = next(a for a in PRIMARY_ARTIFACTS if a in artifacts)
    primary_path = out_dir / primary
    if sha256_file(primary_path) != artifacts[primary]["sha256"]:
        raise MapError(f"{primary} differs from artifacts.json; rebuild or re-run make build")
    app_pkg = raw["app"].packages[0]
    root = Package(
        spdx_id="SPDXRef-firmware", name=prod["name"], version=fw_version,
        download_location=SpdxNoAssertion(), file_name=primary,
        supplier=actor(prod["supplier"]), files_analyzed=False,
        checksums=[Checksum(ChecksumAlgorithm.SHA256, sha_of(primary_path, "sha256")),
                   Checksum(ChecksumAlgorithm.SHA512, sha_of(primary_path, "sha512"))],
        license_concluded=app_pkg.license_concluded,
        license_declared=spdxio.license(prod["license_declared"]),
        copyright_text=SpdxNoAssertion(),
        primary_package_purpose=(PackagePurpose.APPLICATION if primary == "zephyr.exe"
                                 else PackagePurpose.FIRMWARE),
        external_references=[ext_ref(prod["purl"].format(version=fw_version))],
        comment=(f"Release {version} for {board}. Application sources: "
                 f"{files_per_package(raw['app']).get(app_pkg.spdx_id, 0)} files (app.spdx). "
                 "Artifacts (sha256): "
                 + ", ".join(f"{n} {a['sha256']}" for n, a in sorted(artifacts.items()))),
    )
    root_c = Component("firmware", root, "app.spdx + map", files=0)
    root_c.entry = {"id": "product", **prod}
    components: list[Component] = []

    # -- source trees from zephyr.spdx, identifiers from modules-deps.spdx ----------------
    deps = {stem(p.spdx_id): p for p in raw["modules-deps"].packages}
    counts = files_per_package(raw["zephyr"])
    by_raw: dict[str, Component] = {}
    empty: set[str] = set()
    for src in raw["zephyr"].packages:
        name = re.sub(r"-sources$", "", src.name)
        nfiles = counts.get(src.spdx_id, 0)
        if nfiles == 0:
            report["dropped"].append({"component": name, "reason": "0 source files in this build"})
            empty.add(src.name)
            continue
        dep = deps.get(stem(src.spdx_id))
        refs = list(src.external_references)
        for r in (dep.external_references if dep else []):
            if r.locator not in {x.locator for x in refs}:
                refs.append(r)
        pkg = Package(
            spdx_id=spdx_id(name), name=name,
            version=(dep.version if dep and dep.version else src.version),
            download_location=src.download_location,
            supplier=src.supplier or (dep.supplier if dep else None),
            files_analyzed=False,
            license_concluded=src.license_concluded,
            license_declared=SpdxNoAssertion(), copyright_text=SpdxNoAssertion(),
            primary_package_purpose=PackagePurpose.LIBRARY,
            external_references=refs,
            comment=f"{nfiles} source files in this build (zephyr.spdx {src.spdx_id}).",
        )
        components.append(Component(name, pkg, "west spdx", files=nfiles))
        by_raw[src.name] = components[-1]

    # -- SDK files: who covers them ------------------------------------------------------
    sdk_files = {f.name: next((c.value for c in f.checksums
                                if c.algorithm == ChecksumAlgorithm.SHA256), "")
                 for f in raw["sdk"].files}
    covered: set[str] = set()
    app_files = {f.name: next((c.value for c in f.checksums
                               if c.algorithm == ChecksumAlgorithm.SHA256), "")
                 for f in raw["app"].files}
    vendored: set[str] = set()

    for entry in cmap["components"]:
        if "spdx_package" in entry:
            target = by_raw.get(entry["spdx_package"])
            if target is None:
                why = ("0 source files in this build" if entry["spdx_package"] in empty
                       else f"no package {entry['spdx_package']} in zephyr.spdx")
                report["map_unused"].append({"entry": entry["id"], "reason": why})
                continue
            if target.package.version != entry["version"]:
                raise MapError(f"map entry '{entry['id']}' was written for version {entry['version']}, "
                               f"build has {target.package.version}: review the entry again")
            apply_entry(target, entry)
            target.source += " + map"
        elif "app_paths" in entry["evidence_required"]:
            # a library copied into the application tree (no package metadata)
            ev = entry["evidence_required"]
            files = [f for f in app_files if any(f.startswith(p) for p in ev["app_paths"])]
            if not files:
                report["map_unused"].append({"entry": entry["id"], "reason": "files not in this build"})
                continue
            bad = [path_ for path_, digest in ev.get("app_file_sha256", {}).items()
                   if app_files.get(path_) != digest]
            if bad:
                raise MapError(f"map entry '{entry['id']}': {', '.join(bad)} changed or missing in "
                               "app.spdx -- library updated? review the entry again")
            vendored.update(files)
            pkg = Package(
                spdx_id=spdx_id(entry["id"]), name=entry["id"], version=entry["version"],
                download_location=SpdxNoAssertion(), files_analyzed=False,
                license_concluded=SpdxNoAssertion(), license_declared=SpdxNoAssertion(),
                copyright_text=SpdxNoAssertion(), primary_package_purpose=PackagePurpose.LIBRARY,
                comment=(f"Vendored into the application tree: {len(files)} files under "
                         f"{', '.join(ev['app_paths'])} in app.spdx."),
            )
            c = Component(entry["id"], pkg, "map", files=len(files))
            apply_entry(c, entry)
            c.added.insert(0, f"component added, version {entry['version']}")
            components.append(c)
        else:
            ev = entry["evidence_required"]
            files = [f for f in sdk_files if any(f.startswith(p) for p in ev["sdk_paths"])]
            missing = [why for ok, why in [
                (ev["linked_archive"] in linked, f"{ev['linked_archive']} not linked"),
                (bool(files), "no SDK files under " + ", ".join(ev["sdk_paths"])),
            ] if not ok]
            for path_, digest in ev.get("sdk_file_sha256", {}).items():
                if sdk_files.get(path_) != digest:
                    missing.append(f"{path_} hash differs or missing in sdk.spdx")
            if not files:
                # this toolchain is not used by the build (e.g. native_sim uses the host gcc)
                report["map_unused"].append({"entry": entry["id"],
                                             "reason": "SDK toolchain files not in this build"})
                continue
            if missing:
                # the toolchain is used but no longer matches what the entry was written for
                raise MapError(f"map entry '{entry['id']}': " + "; ".join(missing)
                               + " -- toolchain changed? review the entry again")
            covered.update(files)
            linked.discard(ev["linked_archive"])
            pkg = Package(
                spdx_id=spdx_id(entry["id"]), name=entry["id"], version=entry["version"],
                download_location=SpdxNoAssertion(), files_analyzed=False,
                license_concluded=SpdxNoAssertion(), license_declared=SpdxNoAssertion(),
                copyright_text=SpdxNoAssertion(), primary_package_purpose=PackagePurpose.LIBRARY,
                comment=(f"Not described by west spdx. Evidence: {ev['linked_archive']} in the "
                         f"linker map, {len(files)} SDK files in sdk.spdx."),
            )
            c = Component(entry["id"], pkg, "map", files=len(files))
            apply_entry(c, entry)
            c.added.insert(0, f"component added, version {entry['version']}")
            components.append(c)

    if vendored:
        root.comment = (root.comment or "") + (f" {len(vendored)} of the application files are a "
                                               "vendored library, listed as its own component.")
    # Files in the application tree outside src/ are often copied third-party code.
    # Without a map entry nobody can tell what they are; say so instead of guessing.
    stray = sorted(f for f in app_files if not f.startswith("./src/") and f not in vendored)
    if stray:
        report["gaps"].append(f"{len(stray)} application files outside src/ are not attributed "
                              f"to any component (e.g. {stray[0]})")

    # -- gaps that stay visible ----------------------------------------------------------
    uncovered = sorted(set(sdk_files) - covered)
    if uncovered:
        report["gaps"].append(f"{len(uncovered)} SDK files not assigned to a component "
                              f"(e.g. {uncovered[0]})")
    for archive in sorted(linked):
        report["gaps"].append(f"{archive} is linked but no component describes it")
    if summary.get("host_libc_not_described"):
        report["gaps"].append("host C library (native_sim, dynamically linked) not described")

    # -- annotations for every map-sourced change ---------------------------------------------
    annotations = []
    root_changes = ["product package from map: supplier, PURL, declared license"]
    annotations.append(annotate(root_c, root_c.entry, root_changes))
    for c in components:
        if c.entry is not None:
            annotations.append(annotate(c, c.entry, c.added or ["no change needed"]))
    for e in [prod] + list(cmap["components"]):
        if not e["reviewed_by"]:
            report["unreviewed"].append(e.get("id", "product"))

    # -- document ------------------------------------------------------------------------
    elf16 = artifacts["zephyr.elf"]["sha256"][:16]
    map_sha = sha256_file(map_file)
    report["inputs"] = {f"sbom/{n}.spdx": sha256_file(sbom / f"{n}.spdx") for n in raw}
    report["inputs"]["sbom/summary.json"] = sha256_file(sbom / "summary.json")
    report["inputs"]["artifacts.json"] = sha256_file(out_dir / "artifacts.json")
    report["inputs"]["identifiers/component-map.yaml"] = map_sha
    inputs_sha = hashlib.sha256(json.dumps(report["inputs"], sort_keys=True).encode()).hexdigest()
    board_dir = board.replace("/", "_")
    ext_docs = [ExternalDocumentRef(f"DocumentRef-raw-{n}", raw[n].creation_info.document_namespace,
                                    Checksum(ChecksumAlgorithm.SHA1, sha_of(sbom / f"{n}.spdx", "sha1")))
                for n in ("app", "zephyr", "build", "modules-deps", "sdk")]
    creators = sorted({str(a) for d in raw.values() for a in d.creation_info.creators})
    info = CreationInfo(
        spdx_version="SPDX-2.3", spdx_id="SPDXRef-DOCUMENT",
        name=f"{prod['name']}-{version}-{board_dir}",
        document_namespace=(f"https://spdx.org/spdxdocs/cra-evidence-demo/{version}/{board_dir}/"
                            f"{elf16}/normalized-{inputs_sha[:16]}"),
        creators=[actor(s) for s in creators] + [TOOL],
        created=max(d.creation_info.created for d in raw.values()),
        creator_comment=(f"Normalized from the west spdx documents referenced as DocumentRef-raw-* "
                         f"with identifiers/component-map.yaml (sha256 {map_sha})."),
        external_document_refs=ext_docs,
    )
    rels = [Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, root.spdx_id)]
    rels += [Relationship(root.spdx_id, RelationshipType.STATIC_LINK, c.package.spdx_id)
             for c in components]
    doc = Document(info, packages=[root] + [c.package for c in components],
                   annotations=annotations, relationships=rels)

    report["components"] = [
        {"id": c.id, "spdx_id": c.package.spdx_id, "version": c.package.version,
         "supplier": str(c.package.supplier) if c.package.supplier else None,
         "identifiers": [r.locator for r in c.package.external_references],
         "source": c.source, "files": c.files, "map_changes": c.added}
        for c in [root_c] + components]
    report["dropped"].append({"component": "build.spdx targets",
                              "reason": f"{len(raw['build'].packages)} CMake targets are build "
                                        "steps, not components (raw document kept)"})
    return doc, report


def render(report: dict[str, Any], board: str, version: str) -> None:
    table = Table(title=f"Normalized SBOM  |  {version}  |  {board}")
    for col in ("Component", "Version", "Supplier", "CPE", "PURL", "From"):
        table.add_column(col, no_wrap=True, overflow="ellipsis",
                         max_width=22 if col == "Supplier" else None)
    for c in report["components"]:
        ids = c["identifiers"]
        added = set(" ".join(c["map_changes"]).split())
        def cnt(prefix: str) -> str:
            mine = [i for i in ids if i.startswith(prefix)]
            new = [i for i in mine if i in added]
            if not mine:
                return "[red]-[/]"
            return f"{len(mine)}" + (f" [green](+{len(new)})[/]" if new else "")
        v = c["version"] or "-"
        v = v[:12] if re.fullmatch(r"[0-9a-f]{40}", v) else v
        sup = escape(c["supplier"].split(": ", 1)[-1]) if c["supplier"] else "[red]-[/]"
        table.add_row(c["id"], v, sup, cnt("cpe:"), cnt("pkg:"), c["source"])
    console.print(table)
    for d in report["dropped"]:
        console.print(f"dropped: {d['component']} ({d['reason']})")
    for g in report["gaps"]:
        console.print(f"[yellow]gap:[/] {escape(g)}")
    if report["map_unused"]:
        console.print("map entries not used by this build: "
                      + ", ".join(u["entry"] for u in report["map_unused"]) + " (see report.json)")
    if report["unreviewed"]:
        console.print(f"[yellow]{len(report['unreviewed'])} map entries not reviewed by a person[/] "
                      "(identifiers/component-map.yaml: reviewed_by)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--map", type=Path, default=MAP_FILE, help="component map (default: %(default)s)")
    args = parser.parse_args(argv)

    target = args.out_dir / validate.NORMALIZED
    # never leave a previous run's SBOM behind when this run fails
    for stale in (target, target.parent / "report.json"):
        stale.unlink(missing_ok=True)
    try:
        cmap = load_map(args.map)
        doc, report = build(args.out_dir, args.board, args.version, cmap, args.map)
    except (MapError, FileNotFoundError) as exc:
        console.print(f"[bold red]normalize: {escape(str(exc))}[/]")
        return 1
    spdxio.write_json(doc, target)
    (target.parent / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    render(report, args.board, args.version)

    r = validate.check(target, str(validate.NORMALIZED), args.out_dir / "validate")
    ok = not r.spdx_errors and r.ntia.compliant
    console.print(f"{validate.NORMALIZED}: SPDX 2.3 {'valid' if not r.spdx_errors else 'INVALID'}, "
                  f"NTIA {validate.ntia_cell(r.ntia)}, FSCT3 {validate.fsct_cell(r.fsct3)}, "
                  f"CPE/PURL {r.with_ids}/{r.reachable}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
