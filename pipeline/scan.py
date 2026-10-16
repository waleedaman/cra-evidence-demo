# SPDX-License-Identifier: Apache-2.0
"""Scan the normalized SBOM with Grype and OSV-Scanner against a frozen DB snapshot.

  python -m pipeline.scan --out-dir out/v1.0/<board> --board <board> --version v1.0 \
                          [--snapshot baseline]

Input:  out/<v>/<board>/normalized/firmware.spdx.json (make normalize)
        the snapshot from vulndb/snapshots.yaml, imported by make fetch
Output: out/<v>/<board>/scan/<snapshot>/grype.json         raw Grype report
        out/<v>/<board>/scan/<snapshot>/osv-scanner-custom.json, osv.json   OSV input + report
        out/<v>/<board>/scan/<snapshot>/findings.json      merged (kept per snapshot)
        out/<v>/<board>/findings.json                      merged, latest scan (make queue)

Grype reads the SPDX file directly and matches the CPEs of every package (NVD data).

OSV-Scanner 2.7.0 cannot use this SBOM directly for C components (checked in its source,
see docs/scanning.md): it maps pkg:github PURLs to the "GitHub Actions" ecosystem, and
offline it skips commit-only GIT queries. Its offline GIT matcher does work for
"repository URL + release tag". So we write those pairs, derived from each package's
pkg:github PURL, to OSV-Scanner's own custom input format (-L osv-scanner:<file>) and
let OSV-Scanner do the matching. Components without a release tag are reported as not
checkable offline instead of silently passing.

Every finding is deduplicated by (vulnerability ID, component) and keeps which scanner
found it. Snapshot name, build/record date and archive sha256 go into every report.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.markup import escape
from rich.table import Table

from pipeline import vulndb
from pipeline.common import ARCHIVE_DIR, CACHE_DIR, GRYPE_CONFIG, console, run, sha256_file

NORMALIZED = Path("normalized") / "firmware.spdx.json"
SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}
COMMIT = re.compile(r"[0-9a-f]{40}")


class ScanError(Exception):
    pass


@dataclass
class Component:
    name: str
    spdx_id: str
    version: str
    purl: str | None
    cpes: list[str]
    osv_repos: list[str] = field(default_factory=list)  # repo URLs queried
    osv_tag: str | None = None
    osv_note: str = ""
    grype_hits: int = 0
    osv_hits: int = 0


def cvss_rating(score: float | None) -> str:
    """CVSS v3.x qualitative rating (FIRST CVSS v3.1 specification, section 5)."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"


def canonical_id(vid: str, aliases: list[str]) -> str:
    if vid.startswith("CVE-"):
        return vid
    cves = sorted(a for a in aliases if a.startswith("CVE-"))
    return cves[0] if cves else vid


# ------------------------------------------------------------------ components


def load_components(sbom: dict[str, Any]) -> tuple[dict[str, Any], list[Component]]:
    root_id = next(r["relatedSpdxElement"] for r in sbom["relationships"]
                   if r["relationshipType"] == "DESCRIBES")
    comps: list[Component] = []
    root: dict[str, Any] = {}
    for p in sbom["packages"]:
        refs = p.get("externalRefs", [])
        purls = [r["referenceLocator"] for r in refs if r["referenceType"] == "purl"]
        cpes = [r["referenceLocator"] for r in refs if r["referenceType"].startswith("cpe")]
        c = Component(p["name"], p["SPDXID"], p.get("versionInfo", ""),
                      purls[0] if purls else None, cpes)
        if p["SPDXID"] == root_id:
            root = p
        osv_input(c)
        comps.append(c)
    comps.sort(key=lambda c: c.spdx_id != root_id)   # root (the firmware) first, stable
    return root, comps


def osv_input(c: Component) -> None:
    """Decide how OSV-Scanner can query this component offline (sets osv_* fields)."""
    if not c.purl or not c.purl.startswith("pkg:github/"):
        c.osv_note = "no GitHub PURL"
        return
    m = re.fullmatch(r"pkg:github/([^/]+)/([^@]+)@(.+)", c.purl)
    if not m:
        c.osv_note = "unparsable PURL"
        return
    owner, repo, version = m.groups()
    if COMMIT.fullmatch(version):
        c.osv_note = "commit only (needs online OSV)"
        return
    # GitHub names are case-insensitive, but OSV records spell repos both ways
    # (e.g. Mbed-TLS/mbedtls and mbed-tls/mbedtls) and the matcher compares exactly.
    url = f"https://github.com/{owner}/{repo}"
    c.osv_repos = sorted({url, url.lower()})
    c.osv_tag = version
    c.osv_note = f"repo@{version}"


# ------------------------------------------------------------------ snapshot


def snapshot_info(name: str) -> dict[str, Any]:
    """Check the snapshot is present and unchanged; return what goes into every report."""
    data = vulndb.load_snapshots()
    if name not in data["grype"] or name not in data["osv"]:
        raise ScanError(f"snapshot '{name}' is not recorded in vulndb/snapshots.yaml")
    g, o = data["grype"][name], data["osv"][name]
    status = vulndb.grype_status(name)
    if not status or not vulndb.same_instant(str(status.get("built", "")), str(g["built"])):
        raise ScanError(f"Grype DB '{name}' not imported or different build; run make fetch")
    ecosystems: dict[str, Any] = {}
    for eco, entry in o["ecosystems"].items():
        archive = ARCHIVE_DIR / entry["file"]
        if not archive.exists() or sha256_file(archive) != entry["sha256"]:
            raise ScanError(f"OSV {eco} archive for '{name}' missing or changed; run make fetch")
        ecosystems[eco] = {"sha256": entry["sha256"], "file": entry["file"],
                           "last_modified": entry.get("http_headers", {}).get("Last-Modified", "")}
    return {
        "name": name,
        "grype": {"built": g["built"], "schema_version": g["schema_version"],
                  "sha256": g["sha256"], "file": g["file"]},
        "osv": {"recorded_at": o["recorded_at"], "ecosystems": ecosystems},
    }


def osv_cache_dir(name: str, snap: dict[str, Any]) -> Path:
    """OSV-Scanner 2.7.0 (osv-scalibr) reads <dir>/osv-scalibr/<ecosystem>/all.zip."""
    base = CACHE_DIR / "osv" / name
    for eco, entry in snap["osv"]["ecosystems"].items():
        link = base / "osv-scalibr" / eco / "all.zip"
        link.parent.mkdir(parents=True, exist_ok=True)
        target = ARCHIVE_DIR / entry["file"]
        if link.is_symlink() or link.exists():
            if link.resolve() == target.resolve():
                continue
            link.unlink()
        link.symlink_to(target)
    return base


def osv_cache_with_extra(name: str, snap: dict[str, Any], extra: list[Path]) -> Path:
    """Snapshot + SYNTHETIC records (scenario 5 fallback): a copy of the GIT database with
    the extra OSV JSON records appended. The recorded snapshot itself is never changed."""
    import hashlib
    import shutil
    tag = hashlib.sha256(b"".join(p.read_bytes() for p in extra)).hexdigest()[:12]
    base = CACHE_DIR / "osv" / f"{name}+synthetic-{tag}"
    target = base / "osv-scalibr" / "GIT" / "all.zip"
    if not target.exists():
        entry = snap["osv"]["ecosystems"]["GIT"]
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        shutil.copyfile(ARCHIVE_DIR / entry["file"], tmp)
        with zipfile.ZipFile(tmp, "a") as z:
            for p in extra:
                record = json.loads(p.read_text(encoding="utf-8"))
                if not str(record.get("id", "")).startswith("DEMO-"):
                    raise ScanError(f"{p}: synthetic records must use a DEMO- id")
                z.writestr(f"{record['id']}.json", json.dumps(record))
        tmp.rename(target)
    return base


# ------------------------------------------------------------------ scanners


def tool_version(cmd: list[str], pattern: str) -> str:
    res = run(cmd)
    m = re.search(pattern, res.stdout + res.stderr)
    return m.group(1) if m else "unknown"


def run_grype(sbom: Path, out: Path, snapshot: str) -> dict[str, Any]:
    res = run(["grype", "-c", str(GRYPE_CONFIG), f"sbom:{sbom}", "-o", "json", "--file", str(out)],
              env={"GRYPE_DB_CACHE_DIR": str(vulndb.grype_cache_dir(snapshot))}, timeout=600)
    if not res.ok:
        raise ScanError(f"grype failed (rc {res.returncode}): {res.stderr.strip()[-400:]}")
    report: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return report


def run_osv(comps: list[Component], scan_dir: Path, cache: Path) -> dict[str, Any]:
    packages = [{"package": {"name": repo, "version": c.osv_tag, "ecosystem": "GIT"}}
                for c in comps if c.osv_tag for repo in c.osv_repos]
    custom = scan_dir / "osv-scanner-custom.json"
    custom.write_text(json.dumps({"results": [{"source": {"path": str(NORMALIZED), "type": "sbom"},
                                               "packages": packages}]}, indent=2) + "\n",
                      encoding="utf-8")
    out = scan_dir / "osv.json"
    res = run(["osv-scanner", "scan", "source", "--offline", "-L", f"osv-scanner:{custom}",
               "--format", "json", "--output-file", str(out)],
              env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache)}, timeout=600)
    (scan_dir / "osv.log").write_text(res.stdout + res.stderr, encoding="utf-8")
    # exit codes (cmd/osv-scanner/internal/cmd/run.go): 0 none found, 1 vulnerabilities found
    if res.returncode not in (0, 1):
        raise ScanError(f"osv-scanner failed (rc {res.returncode}): {res.stderr.strip()[-400:]}")
    report: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return report


# ------------------------------------------------------------------ merge


def merge(grype: dict[str, Any], osv: dict[str, Any], comps: list[Component],
          osv_zip: Path | None) -> list[dict[str, Any]]:
    by_name = {c.name: c for c in comps}
    by_repo = {(r, c.osv_tag): c for c in comps for r in c.osv_repos}
    findings: dict[tuple[str, str], dict[str, Any]] = {}

    def entry(vid: str, c: Component) -> dict[str, Any]:
        key = (vid, c.name)
        if key not in findings:
            findings[key] = {"id": vid, "aliases": [], "component": c.name,
                             "component_version": c.version, "component_purl": c.purl,
                             "component_spdx_id": c.spdx_id, "severity": "Unknown",
                             "cvss": None, "score": None, "found_by": [], "summary": "",
                             "urls": []}
        return findings[key]

    for m in grype.get("matches", []):
        v, art = m["vulnerability"], m["artifact"]
        c = by_name.get(art["name"])
        if c is None:
            continue
        aliases = [r["id"] for r in m.get("relatedVulnerabilities", [])]
        f = entry(canonical_id(v["id"], aliases), c)
        if "grype" in f["found_by"]:
            continue
        f["found_by"].append("grype")
        c.grype_hits += 1
        f["aliases"] = sorted((set(f["aliases"]) | set(aliases) | {v["id"]}) - {f["id"]})
        f["severity"] = v.get("severity") or "Unknown"
        cv = next((x for x in v.get("cvss", []) if x.get("source") == "nvd@nist.gov"),
                  (v.get("cvss") or [None])[0])
        if cv:
            f["cvss"], f["score"] = cv.get("vector"), cv.get("metrics", {}).get("baseScore")
        md = m["matchDetails"][0]
        f["grype"] = {"namespace": v.get("namespace"), "matched_cpes": md["searchedBy"].get("cpes", []),
                      "version_constraint": md["found"].get("versionConstraint"),
                      "fix_state": v.get("fix", {}).get("state"),
                      "fix_versions": v.get("fix", {}).get("versions", [])}
        f["summary"] = (v.get("description") or "").strip().split("\n")[0][:200]
        f["urls"] = v.get("urls", [])[:3]

    for res in osv.get("results", []):
        for p in res.get("packages", []):
            c = by_repo.get((p["package"]["name"], p["package"]["version"]))
            if c is None:
                continue
            scores = {i: g.get("max_severity") for g in p.get("groups", []) for i in g.get("ids", [])}
            for v in p.get("vulnerabilities", []):
                f = entry(canonical_id(v["id"], v.get("aliases", [])), c)
                if "osv-scanner" in f["found_by"]:
                    continue
                f["found_by"].append("osv-scanner")
                c.osv_hits += 1
                f["aliases"] = sorted((set(f["aliases"]) | set(v.get("aliases", [])) | {v["id"]})
                                      - {f["id"]})
                score = float(scores[v["id"]]) if scores.get(v["id"]) else None
                if "grype" not in f["found_by"]:
                    f["severity"], f["score"] = cvss_rating(score), score
                    f["cvss"] = next((s["score"] for s in v.get("severity", [])
                                      if s.get("type", "").startswith("CVSS_V3")), None)
                    f["summary"] = (v.get("summary") or v.get("details") or "").split("\n")[0][:200]
                    f["urls"] = [r["url"] for r in v.get("references", [])
                                 if r.get("type") in ("ADVISORY", "FIX")][:3]
                f["osv"] = {"repo": p["package"]["name"], "version": p["package"]["version"],
                            "modified": v.get("modified"), "max_severity": score}

    # What does the OSV data say about Grype-only findings of OSV-checkable components?
    if osv_zip is not None and osv_zip.exists():
        with zipfile.ZipFile(osv_zip) as z:
            names = set(z.namelist())
            for f in findings.values():
                c = by_name[f["component"]]
                if f["found_by"] != ["grype"] or not c.osv_tag:
                    continue
                rec = f"{f['id']}.json"
                if rec not in names:
                    f["osv_view"] = "no OSV record"
                    continue
                d = json.loads(z.read(rec))
                repos = {r.get("repo", "").lower().removesuffix(".git") for a in d.get("affected", [])
                         for r in a.get("ranges", [])}
                if not repos & {r.lower() for r in c.osv_repos}:
                    f["osv_view"] = "OSV record for another repo"
                else:
                    f["osv_view"] = f"OSV record does not list {c.osv_tag}"

    out = list(findings.values())
    out.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["component"], f["id"]))
    return out


# ------------------------------------------------------------------ main


def render(comps: list[Component], snap: dict[str, Any], versions: dict[str, str],
           findings: list[dict[str, Any]], title: str) -> None:
    t = Table(title=title)
    for col in ("Component", "Version", "Grype input"):
        t.add_column(col, no_wrap=True)
    t.add_column("Grype", justify="right")
    t.add_column("OSV-Scanner input", no_wrap=True)
    t.add_column("OSV", justify="right")
    for i, c in enumerate(comps):
        v = c.version[:12] if COMMIT.fullmatch(c.version) else c.version
        name = "firmware" if i == 0 else c.name
        grype_in = f"{len(c.cpes)} CPE" if c.cpes else "[red]no CPE[/]"
        osv_in = c.osv_note if c.osv_tag else f"[yellow]{c.osv_note}[/]"
        t.add_row(name, v, grype_in, str(c.grype_hits) if c.cpes else "-",
                  osv_in, str(c.osv_hits) if c.osv_tag else "-")
    console.print(t)
    g, o = snap["grype"], snap["osv"]
    console.print(f"grype {versions['grype']}: DB '{snap['name']}' built {g['built']}, "
                  f"archive sha256 {g['sha256'][:16]}...")
    for eco, e in o["ecosystems"].items():
        console.print(f"osv-scanner {versions['osv-scanner']}: OSV {eco} recorded {o['recorded_at']}, "
                      f"sha256 {e['sha256'][:16]}...")
    both = sum(1 for f in findings if len(f["found_by"]) == 2)
    g_only = sum(1 for f in findings if f["found_by"] == ["grype"])
    o_only = sum(1 for f in findings if f["found_by"] == ["osv-scanner"])
    disagree = sum(1 for f in findings if f.get("osv_view", "").startswith("OSV record does not list"))
    console.print(f"[bold]{len(findings)} findings[/] -> findings.json: {g_only} Grype only, "
                  f"{o_only} OSV-Scanner only, {both} both")
    console.print(f"{disagree} Grype findings have an OSV record that does not list this version")
    synthetic = [f["id"] for f in findings if f["id"].startswith("DEMO-")]
    if snap.get("synthetic_osv_records"):
        console.print(f"[bold magenta]SYNTHETIC data added to OSV for this scan[/]: "
                      f"{', '.join(r['file'] for r in snap['synthetic_osv_records'])}; "
                      f"synthetic findings: {', '.join(synthetic) or 'none'} (docs/synthetic-data.md)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--snapshot", default="baseline")
    parser.add_argument("--osv-extra", type=Path, nargs="*", default=[],
                        help="SYNTHETIC OSV records (DEMO- ids) added to the OSV data for this scan")
    args = parser.parse_args(argv)

    sbom_path = args.out_dir / NORMALIZED
    if not sbom_path.exists():
        console.print(f"[bold red]{sbom_path} missing: run make normalize first[/]")
        return 1
    scan_dir = args.out_dir / "scan" / args.snapshot
    scan_dir.mkdir(parents=True, exist_ok=True)
    for stale in [args.out_dir / "findings.json", *scan_dir.glob("*.json")]:
        stale.unlink(missing_ok=True)
    try:
        snap = snapshot_info(args.snapshot)
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        root, comps = load_components(sbom)
        cache = (osv_cache_with_extra(args.snapshot, snap, args.osv_extra) if args.osv_extra
                 else osv_cache_dir(args.snapshot, snap))
        if args.osv_extra:
            snap["synthetic_osv_records"] = [{"file": str(p), "sha256": sha256_file(p)}
                                             for p in args.osv_extra]
        grype = run_grype(sbom_path, scan_dir / "grype.json", args.snapshot)
        osv = run_osv(comps, scan_dir, cache)
    except ScanError as exc:
        console.print(f"[bold red]scan: {escape(str(exc))}[/]")
        return 1
    git_entry = snap["osv"]["ecosystems"].get("GIT")
    osv_zip = ARCHIVE_DIR / git_entry["file"] if git_entry else None
    findings = merge(grype, osv, comps, osv_zip)
    versions = {"grype": tool_version(["grype", "version"], r"Version:\s+(\S+)"),
                "osv-scanner": tool_version(["osv-scanner", "--version"], r"osv-scanner version: (\S+)")}
    fw_sha = next((c["checksumValue"] for c in root.get("checksums", [])
                   if c["algorithm"] == "SHA256"), "")
    report = {
        "schema": "cra-evidence-demo/findings/v1",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "product": {"name": root.get("name"), "version": root.get("versionInfo"),
                    "release": args.version, "board": args.board,
                    "firmware_file": root.get("packageFileName"), "firmware_sha256": fw_sha,
                    "purl": next((r["referenceLocator"] for r in root.get("externalRefs", [])
                                  if r["referenceType"] == "purl"), None)},
        "sbom": {"path": str(NORMALIZED), "sha256": sha256_file(sbom_path),
                 "namespace": sbom.get("documentNamespace")},
        "snapshot": snap,
        "tools": versions,
        "coverage": [{"component": c.name, "version": c.version, "cpes": c.cpes,
                      "osv_query": [f"{r}@{c.osv_tag}" for r in c.osv_repos] if c.osv_tag else None,
                      "osv_note": c.osv_note, "grype_hits": c.grype_hits, "osv_hits": c.osv_hits}
                     for c in comps],
        "findings": findings,
    }
    text = json.dumps(report, indent=2) + "\n"
    (scan_dir / "findings.json").write_text(text, encoding="utf-8")
    (args.out_dir / "findings.json").write_text(text, encoding="utf-8")
    render(comps, snap, versions, findings,
           f"Vulnerability scan  |  {args.version}  |  {args.board}  |  snapshot {args.snapshot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
