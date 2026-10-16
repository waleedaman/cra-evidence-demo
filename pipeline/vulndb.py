# SPDX-License-Identifier: Apache-2.0
"""Frozen vulnerability database snapshots.

  record NAME  download the *current* upstream Grype DB and OSV ecosystem archives
               and write their URL, sha256 and dates into vulndb/snapshots.yaml
               (needs network; run deliberately, e.g. `make snapshot NAME=baseline`)
  fetch        make sure every recorded snapshot is present locally and matches its
               recorded sha256, then import the Grype DBs (needs network only for
               archives that are missing locally)
  status       print the recorded snapshots (offline)

Only snapshots.yaml is committed; archives live in vulndb/archives (git-ignored).
Upstream "latest" archives get replaced over time, so a recorded snapshot can only
be re-downloaded while upstream still serves the same bytes. A checksum mismatch
is always a hard failure, never silently accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml
from rich.markup import escape
from rich.table import Table

from pipeline.common import (
    ARCHIVE_DIR,
    CACHE_DIR,
    GRYPE_CONFIG,
    OSV_ECOSYSTEMS_FILE,
    SNAPSHOTS_FILE,
    console,
    run,
    sha256_file,
)

GRYPE_LATEST_URL = "https://grype.anchore.io/databases/v6/latest.json"
OSV_BUCKET_URL = "https://osv-vulnerabilities.storage.googleapis.com"
USER_AGENT = "cra-evidence-demo/vulndb"

HEADER = (
    "# Frozen vulnerability DB snapshots. Written by `make snapshot NAME=<name>`.\n"
    "# Do not edit by hand: `make fetch` and `make doctor` verify archives against\n"
    "# these checksums. Archives themselves are git-ignored (vulndb/archives/).\n"
)


class SnapshotError(Exception):
    pass


# --------------------------------------------------------------------------- io


def load_snapshots() -> dict[str, Any]:
    if not SNAPSHOTS_FILE.exists():
        return {"grype": {}, "osv": {}}
    data = yaml.safe_load(SNAPSHOTS_FILE.read_text(encoding="utf-8")) or {}
    data.setdefault("grype", {})
    data.setdefault("osv", {})
    if data["grype"] is None:
        data["grype"] = {}
    if data["osv"] is None:
        data["osv"] = {}
    return dict(data)


def save_snapshots(data: dict[str, Any]) -> None:
    body = yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
    SNAPSHOTS_FILE.write_text(HEADER + body, encoding="utf-8")


def load_osv_ecosystems() -> list[str]:
    lines = OSV_ECOSYSTEMS_FILE.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": USER_AGENT})


def http_get_bytes(url: str) -> bytes:
    with urllib.request.urlopen(_request(url), timeout=60) as resp:
        data: bytes = resp.read()
        return data


def download(url: str, dest: Path) -> tuple[str, dict[str, str]]:
    """Stream url to dest atomically. Returns (sha256, selected response headers)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    keep = ("Last-Modified", "ETag", "x-goog-generation", "Content-Length")
    with urllib.request.urlopen(_request(url), timeout=60) as resp:
        headers = {k: str(resp.headers[k]) for k in keep if resp.headers.get(k) is not None}
        with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as tmp:
            tmp_path = Path(tmp.name)
            while chunk := resp.read(1 << 20):
                h.update(chunk)
                tmp.write(chunk)
    tmp_path.replace(dest)
    return h.hexdigest(), headers


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


# ----------------------------------------------------------------------- record


def record_grype(name: str) -> dict[str, Any]:
    latest = json.loads(http_get_bytes(GRYPE_LATEST_URL))
    for key in ("path", "checksum", "built", "schemaVersion"):
        if key not in latest:
            raise SnapshotError(f"Grype latest.json has no '{key}' field; format changed?")
    algo, _, expected = str(latest["checksum"]).partition(":")
    if algo != "sha256" or not expected:
        raise SnapshotError(f"unexpected checksum format in latest.json: {latest['checksum']}")
    url = urljoin(GRYPE_LATEST_URL, str(latest["path"]))
    dest = ARCHIVE_DIR / "grype" / name / Path(urlparse(url).path).name
    console.print(f"grype: downloading {url}", soft_wrap=True)
    actual, headers = download(url, dest)
    if actual != expected:
        raise SnapshotError(f"Grype archive sha256 {actual} != latest.json {expected}")
    return {
        "url": url,
        "sha256": actual,
        "built": str(latest["built"]),
        "schema_version": str(latest["schemaVersion"]),
        "listing": GRYPE_LATEST_URL,
        "recorded_at": _now(),
        "file": str(dest.relative_to(ARCHIVE_DIR)),
        "http_headers": headers,
    }


def record_osv(name: str) -> dict[str, Any]:
    wanted = load_osv_ecosystems()
    available = [ln.strip() for ln in
                 http_get_bytes(f"{OSV_BUCKET_URL}/ecosystems.txt").decode().splitlines()
                 if ln.strip()]
    missing = [e for e in wanted if e not in available]
    if missing:
        raise SnapshotError(
            f"OSV ecosystems not in bucket: {missing}. Available: {', '.join(available)}"
        )
    base = ARCHIVE_DIR / "osv" / name
    (base / "ecosystems.txt").parent.mkdir(parents=True, exist_ok=True)
    (base / "ecosystems.txt").write_text("\n".join(available) + "\n", encoding="utf-8")
    entries: dict[str, Any] = {}
    for eco in wanted:
        url = f"{OSV_BUCKET_URL}/{eco}/all.zip"
        # archive layout <snapshot>/osv-scanner/<eco>/all.zip. NOTE: OSV-Scanner 2.7.0 reads
        # <dir>/osv-scalibr/<eco>/all.zip; pipeline/scan.py links it there at scan time.
        dest = base / "osv-scanner" / eco / "all.zip"
        console.print(f"osv: downloading {url}", soft_wrap=True)
        sha, headers = download(url, dest)
        entries[eco] = {
            "url": url,
            "sha256": sha,
            "file": str(dest.relative_to(ARCHIVE_DIR)),
            "http_headers": headers,
        }
    return {"recorded_at": _now(), "ecosystems": entries}


def cmd_record(name: str, force: bool) -> int:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", name):
        console.print("[bold red]invalid snapshot name[/]: use lowercase letters, digits and '-'")
        return 2
    data = load_snapshots()
    if not force and (name in data["grype"] or name in data["osv"]):
        console.print(f"[bold red]snapshot '{name}' already recorded[/] (use FORCE=1 to replace)")
        return 1
    data["grype"][name] = record_grype(name)
    data["osv"][name] = record_osv(name)
    save_snapshots(data)
    console.print(f"[bold green]recorded snapshot '{name}'[/] -> {SNAPSHOTS_FILE.name}")
    return 0


# ------------------------------------------------------------------------ fetch


def ensure_archive(entry: dict[str, Any], label: str) -> str:
    """Make sure the archive exists and matches.

    Order: local copy -> mirror directory (CRA_VULNDB_MIRROR, read-only, same layout
    as vulndb/archives) -> upstream URL. Every source is checked against the recorded
    sha256. Returns 'cached', 'from mirror' or 'downloaded'.
    """
    dest = ARCHIVE_DIR / str(entry["file"])
    expected = str(entry["sha256"])
    if dest.exists() and sha256_file(dest) == expected:
        return "cached"
    mirror = os.environ.get("CRA_VULNDB_MIRROR")
    if mirror:
        src = Path(mirror) / str(entry["file"])
        if src.exists() and sha256_file(src) == expected:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            return "from mirror"
    console.print(f"{label}: downloading {entry['url']}", soft_wrap=True)
    actual, _ = download(str(entry["url"]), dest)
    if actual != expected:
        bad = dest.with_suffix(dest.suffix + ".mismatch")
        shutil.move(dest, bad)
        raise SnapshotError(
            f"{label}: upstream bytes changed (sha256 {actual[:16]}... != recorded "
            f"{expected[:16]}...). The recorded snapshot is no longer served upstream; "
            "use VULNDB_MIRROR=<dir with the recorded archives> or record a new snapshot."
        )
    return "downloaded"


def grype_cache_dir(name: str) -> Path:
    return CACHE_DIR / "grype" / name


def grype_status(name: str) -> dict[str, Any] | None:
    res = run(["grype", "-c", str(GRYPE_CONFIG), "db", "status", "-o", "json"],
              env={"GRYPE_DB_CACHE_DIR": str(grype_cache_dir(name))})
    if not res.ok:
        return None
    try:
        parsed: dict[str, Any] = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    return parsed


def same_instant(a: str, b: str) -> bool:
    try:
        return datetime.fromisoformat(a) == datetime.fromisoformat(b)
    except ValueError:
        return a == b


def import_grype(name: str, entry: dict[str, Any]) -> str:
    status = grype_status(name)
    if status and same_instant(str(status.get("built", "")), str(entry["built"])):
        return "already imported"
    archive = ARCHIVE_DIR / str(entry["file"])
    res = run(["grype", "-c", str(GRYPE_CONFIG), "db", "import", str(archive)],
              env={"GRYPE_DB_CACHE_DIR": str(grype_cache_dir(name))}, timeout=900)
    if not res.ok:
        raise SnapshotError(f"grype db import failed: {res.stderr.strip()[-400:]}")
    status = grype_status(name)
    if not status or not same_instant(str(status.get("built", "")), str(entry["built"])):
        raise SnapshotError(f"grype db status after import does not match recorded build date: {status}")
    return "imported"


def cmd_fetch(only: list[str] | None = None) -> int:
    data = load_snapshots()
    if only:
        data = {"grype": {k: v for k, v in data["grype"].items() if k in only},
                "osv": {k: v for k, v in data["osv"].items() if k in only}}
    if not data["grype"] and not data["osv"]:
        console.print("[bold red]no snapshot recorded[/]: run `make snapshot NAME=baseline` first")
        return 1
    table = Table(title="Vulnerability DB snapshots", show_lines=False)
    for col in ("Snapshot", "Source", "Archive", "Import"):
        table.add_column(col)
    failed = False
    for name, entry in sorted(data["grype"].items()):
        try:
            state = ensure_archive(entry, f"grype/{name}")
        except SnapshotError as exc:
            failed = True
            table.add_row(name, "grype", "[red]FAIL[/]", escape(str(exc)))
            continue
        try:
            imp = import_grype(name, entry)
        except SnapshotError as exc:
            failed = True
            imp = f"[red]FAIL[/] {escape(str(exc))}"
        table.add_row(name, "grype", f"sha256 OK ({state})", imp)
    for name, snap in sorted(data["osv"].items()):
        for eco, entry in sorted(snap["ecosystems"].items()):
            try:
                state = ensure_archive(entry, f"osv/{name}/{eco}")
                table.add_row(name, f"osv {eco}", f"sha256 OK ({state})", "n/a (zip used directly)")
            except SnapshotError as exc:
                failed = True
                table.add_row(name, f"osv {eco}", "[red]FAIL[/]", escape(str(exc)))
    console.print(table)
    return 1 if failed else 0


def cmd_status() -> int:
    data = load_snapshots()
    table = Table(title="Recorded snapshots (vulndb/snapshots.yaml)")
    for col in ("Snapshot", "Source", "Built / Last-Modified", "sha256"):
        table.add_column(col)
    for name, entry in sorted(data["grype"].items()):
        table.add_row(name, "grype", str(entry["built"]), str(entry["sha256"])[:16] + "...")
    for name, snap in sorted(data["osv"].items()):
        for eco, entry in sorted(snap["ecosystems"].items()):
            lm = entry.get("http_headers", {}).get("Last-Modified", "?")
            table.add_row(name, f"osv {eco}", lm, str(entry["sha256"])[:16] + "...")
    console.print(table)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("name")
    rec.add_argument("--force", action="store_true")
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--only", default="", help="comma-separated snapshot names (CI)")
    sub.add_parser("status")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "record":
            return cmd_record(args.name, args.force)
        if args.cmd == "fetch":
            return cmd_fetch([n for n in args.only.split(",") if n])
        return cmd_status()
    except (SnapshotError, OSError) as exc:
        console.print(f"[bold red]ERROR[/] {escape(str(exc))}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
