# SPDX-License-Identifier: Apache-2.0
"""`make doctor`: verify every pin, checksum and the offline setup.

Runs inside the demo image with `--network none`. Prints one table and writes the
full result to out/doctor.json. Exit code 1 if any check FAILs.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from dataclasses import asdict, dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.table import Table

from pipeline import lockdoc
from pipeline.common import (
    ARCHIVE_DIR,
    GRYPE_CONFIG,
    OUT_DIR,
    REPO,
    REQUIREMENTS_LOCK,
    WORKSPACE,
    console,
    load_pins,
    load_requirements,
    normalize_dist_name,
    run,
    sha256_file,
)
from pipeline.vulndb import grype_status, load_snapshots, same_instant

IMAGE_DIR = Path("/opt/cra")
# pins.env keys baked into the image by docker/install-tools.sh
IMAGE_PIN_PREFIXES = ("ZEPHYR_SDK_", "GRYPE_", "OSV_SCANNER_", "VEXCTL_", "COSIGN_", "JQ_")
SDK_DIR = Path(os.environ.get("ZEPHYR_SDK_INSTALL_DIR", "/opt/toolchains/zephyr-sdk"))


@dataclass
class Check:
    name: str
    expected: str
    actual: str
    result: str  # PASS | FAIL | INFO


CHECKS: list[Check] = []


def add(name: str, expected: str, actual: str, ok: bool | None) -> None:
    result = "INFO" if ok is None else ("PASS" if ok else "FAIL")
    CHECKS.append(Check(name, expected, actual, result))


def short(sha: str) -> str:
    return sha[:12] if sha else "-"


# ------------------------------------------------------------------ checks


def check_network() -> None:
    """Prove the container is offline: no DNS, no outbound TCP."""
    reachable: list[str] = []
    try:
        socket.getaddrinfo("github.com", 443)
        reachable.append("dns")
    except OSError:
        pass
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            reachable.append("tcp")
    except OSError:
        pass
    add("Network", "none", "reachable: " + ",".join(reachable) if reachable else "none",
        not reachable)


def check_image(pins: dict[str, str]) -> None:
    if os.environ.get("CRA_IN_IMAGE") != "1":
        add("Demo image", "running inside image", "not inside image", False)
        return
    # Only the pins that docker/install-tools.sh consumes affect the image. Other
    # pins (modules, Mosquitto, recorded dates) must not force an image rebuild.
    baked = load_pins(IMAGE_DIR / "pins.env") if (IMAGE_DIR / "pins.env").exists() else {}
    changed = sorted(k for k in set(baked) | set(pins)
                     if k.startswith(IMAGE_PIN_PREFIXES) and baked.get(k) != pins.get(k))
    same_reqs = (IMAGE_DIR / "requirements.lock").exists() and \
        sha256_file(IMAGE_DIR / "requirements.lock") == sha256_file(REQUIREMENTS_LOCK)
    if not baked:
        changed = ["(no pins.env in image)"]
    if not same_reqs:
        changed.append("requirements.lock")
    for recipe in ("Dockerfile", "install-tools.sh"):
        baked_file = IMAGE_DIR / recipe
        if not baked_file.exists() or sha256_file(baked_file) != sha256_file(REPO / "docker" / recipe):
            changed.append(recipe)
    add("Image built from current pins", "tool pins, lock, recipe",
        "match" if not changed else f"stale ({', '.join(changed)[:30]}): make env",
        not changed)
    want = f"{pins['CI_BASE_IMAGE']}@{pins['CI_BASE_DIGEST']}"
    have = os.environ.get("CRA_BASE_IMAGE", "")
    add("Base image", short(pins["CI_BASE_DIGEST"].removeprefix("sha256:")),
        short(have.split("@sha256:")[-1]) if "@sha256:" in have else have or "-",
        bool(pins["CI_BASE_DIGEST"]) and have == want)
    image_id = os.environ.get("CRA_IMAGE_ID", "")
    add("Demo image ID", "-", short(image_id.removeprefix("sha256:")) or "-", None)


def check_installed_hashes() -> None:
    manifest = IMAGE_DIR / "installed.sha256"
    if not manifest.exists():
        add("Installed binaries", "match build record", "no record", False)
        return
    bad: list[str] = []
    for line in manifest.read_text().splitlines():
        sha, path = line.split(maxsplit=1)
        p = Path(path.strip())
        if not p.exists() or sha256_file(p) != sha:
            bad.append(p.name)
    add("Installed binaries", "match build record", "modified: " + ",".join(bad) if bad else "match",
        not bad)


def first_line_with(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle in line:
            return line.strip()
    return text.strip().splitlines()[0] if text.strip() else "-"


def check_tool(label: str, cmd: list[str], version: str, binary: Path | None = None,
               release_sha: str | None = None) -> None:
    res = run(cmd)
    out = res.stdout + res.stderr
    ok = res.ok and version in out
    if res.returncode == 127:
        actual = "not found"
    elif ok:
        actual = first_line_with(out, version)
    else:
        actual = (out.strip().splitlines() or ["no output"])[0]
    if ok and binary is not None and release_sha is not None:
        if sha256_file(binary) != release_sha:
            ok, actual = False, f"{actual} (sha256 != release)"
    add(label, version, actual[:48], ok)


def check_tools(p: dict[str, str]) -> None:
    sdk_version_file = SDK_DIR / "sdk_version"
    sdk_actual = sdk_version_file.read_text().strip() if sdk_version_file.exists() else "missing"
    add("Zephyr SDK", p["ZEPHYR_SDK_VERSION"], sdk_actual, sdk_actual == p["ZEPHYR_SDK_VERSION"])
    gcc = SDK_DIR / "gnu" / "arm-zephyr-eabi" / "bin" / "arm-zephyr-eabi-gcc"
    res = run([str(gcc), "--version"])
    add("arm-zephyr-eabi-gcc", "runs", (res.stdout.splitlines() or ["not found"])[0][:48], res.ok)
    check_tool("grype", ["grype", "version"], p["GRYPE_VERSION"])
    bin_dir = Path("/usr/local/bin")
    check_tool("osv-scanner", ["osv-scanner", "--version"], p["OSV_SCANNER_VERSION"],
               bin_dir / "osv-scanner", p["OSV_SCANNER_SHA256"])
    check_tool("vexctl", ["vexctl", "version"], p["VEXCTL_VERSION"],
               bin_dir / "vexctl", p["VEXCTL_SHA256"])
    check_tool("cosign", ["cosign", "version"], p["COSIGN_VERSION"],
               bin_dir / "cosign", p["COSIGN_SHA256"])
    check_tool("jq", ["jq", "--version"], p["JQ_VERSION"], bin_dir / "jq", p["JQ_SHA256"])
    for label, cmd in (("west", ["west", "--version"]), ("cmake", ["cmake", "--version"]),
                       ("openssl (make certs)", ["openssl", "version"]),
                       ("host gcc (native_sim)", ["gcc", "--version"])):
        res = run(cmd)
        add(label, "-", (res.stdout.splitlines() or ["not found"])[0][:48], None if res.ok else False)


def check_python() -> None:
    v = sys.version_info
    want = load_requirements()
    wrong: list[str] = []
    for name, version in want.items():
        try:
            have = metadata.version(name)
        except metadata.PackageNotFoundError:
            wrong.append(f"{name} missing")
            continue
        if have != version:
            wrong.append(f"{name} {have}")
    installed = {normalize_dist_name(d.metadata["Name"]) for d in metadata.distributions()}
    extra = sorted(installed - set(want) - {"pip"})
    ok = (v.major, v.minor) == (3, 12) and not wrong
    detail = f"py {v.major}.{v.minor}.{v.micro}, {len(want) - len(wrong)}/{len(want)} pkgs"
    if wrong:
        detail += " | " + ", ".join(wrong[:3])
    if extra:
        detail += " | extra: " + ", ".join(extra[:3])
    add("Python pipeline venv", "3.12 + requirements.lock", detail[:48], ok and not extra)


def git_head(path: Path) -> tuple[str, bool]:
    head = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    dirty = run(["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"])
    return head.stdout.strip(), head.ok and dirty.ok and not dirty.stdout.strip()


def check_workspace(p: dict[str, str]) -> None:
    manifest = yaml.safe_load((REPO / "west.yml").read_text())["manifest"]
    zephyr_rev = next(pr["revision"] for pr in manifest["projects"] if pr["name"] == "zephyr")
    add("west.yml zephyr revision", short(p["ZEPHYR_COMMIT"]), short(zephyr_rev),
        zephyr_rev == p["ZEPHYR_COMMIT"])
    if not (WORKSPACE / ".west").is_dir():
        add("West workspace", "initialised", "missing: run `make fetch`", False)
        return
    expected = {"zephyr": p["ZEPHYR_COMMIT"]}
    for key, value in p.items():
        if key.startswith("MODULE_") and key.endswith("_SHA"):
            expected[key.removeprefix("MODULE_").removesuffix("_SHA").lower()] = value
    res = run(["west", "list", "-f", "{name}|{abspath}"], cwd=REPO)
    if not res.ok:
        add("West workspace", "west list ok", res.stderr.strip()[:48], False)
        return
    listed: dict[str, Path] = {}
    for line in res.stdout.splitlines():
        name, _, path = line.partition("|")
        if name != "manifest":
            # pins.env keys use "_" where west project names use "-" (tf-psa-crypto)
            listed[name.replace("-", "_")] = Path(path)
    unexpected = sorted(set(listed) - set(expected))
    missing = sorted(set(expected) - set(listed))
    add("West project set", ",".join(sorted(expected)),
        "match" if not (unexpected or missing) else f"extra {unexpected} missing {missing}"[:48],
        not unexpected and not missing)
    tag = p["ZEPHYR_VERSION"]
    if "zephyr" in listed:
        res_tag = run(["git", "-C", str(listed["zephyr"]), "rev-parse", "--verify", "-q",
                       f"{tag}^{{commit}}"])
        tag_sha = res_tag.stdout.strip()
        add(f"  zephyr tag {tag}", short(p["ZEPHYR_COMMIT"]),
            short(tag_sha) if tag_sha else "missing: run `make fetch` (Zephyr CPE in SBOM)",
            tag_sha == p["ZEPHYR_COMMIT"])
    for name in sorted(expected):
        if name not in listed:
            continue
        head, clean = git_head(listed[name])
        actual = short(head) + ("" if clean else " (dirty)")
        add(f"  {name}", short(expected[name]), actual, head == expected[name] and clean)


def check_grype_config() -> None:
    res = run(["grype", "-c", str(GRYPE_CONFIG), "config", "--load"])
    try:
        cfg: Any = yaml.safe_load(res.stdout) if res.ok else None
        db = cfg["db"]
        ok = (cfg["check-for-app-update"] is False and db["auto-update"] is False
              and db["validate-age"] is False)
        actual = (f"update={db['auto-update']} age={db['validate-age']} "
                  f"app={cfg['check-for-app-update']}")
    except (yaml.YAMLError, KeyError, TypeError):
        ok, actual = False, "could not read `grype config --load`"
    add("Grype offline config", "no update, no age check", actual[:48], ok)


def check_snapshots() -> None:
    snaps = load_snapshots()
    only = [n for n in os.environ.get("CRA_SNAPSHOTS", "").split(",") if n]
    if only:   # make doctor SNAPSHOTS=mine: check only the snapshots this clone fetched
        snaps = {"grype": {k: v for k, v in snaps["grype"].items() if k in only},
                 "osv": {k: v for k, v in snaps["osv"].items() if k in only}}
    if not snaps["grype"] and not snaps["osv"]:
        add("DB snapshots", "recorded", "none: run `make snapshot NAME=baseline`", False)
        return
    for name, e in sorted(snaps["grype"].items()):
        f = ARCHIVE_DIR / str(e["file"])
        ok_archive = f.exists() and sha256_file(f) == e["sha256"]
        status = grype_status(name)
        imported = bool(status) and same_instant(str(status.get("built", "")) if status else "",
                                                 str(e["built"]))
        actual = ("sha OK" if ok_archive else "archive missing/bad") + \
                 (", imported" if imported else ", not imported")
        add(f"Grype DB '{name}'", f"built {str(e['built'])[:10]}", actual, ok_archive and imported)
    for name, s in sorted(snaps["osv"].items()):
        bad = [eco for eco, e in s["ecosystems"].items()
               if not (ARCHIVE_DIR / str(e["file"])).exists()
               or sha256_file(ARCHIVE_DIR / str(e["file"])) != e["sha256"]]
        add(f"OSV DB '{name}'", ",".join(sorted(s["ecosystems"])),
            "sha OK" if not bad else f"missing/bad: {','.join(bad)}", not bad)


def check_vendored(p: dict[str, str]) -> None:
    f = REPO / "schema" / "vendor" / "openvex_json_schema.json"
    ok = f.exists() and sha256_file(f) == p.get("OPENVEX_SCHEMA_SHA256", "")
    add("OpenVEX schema (vendored)", short(p.get("OPENVEX_SCHEMA_SHA256", "")),
        "sha OK" if ok else "missing or modified", ok)


def check_lockdoc(p: dict[str, str]) -> None:
    digest = p["CI_BASE_DIGEST"].removeprefix("sha256:")
    add("Base digest recorded", "set in pins.env",
        short(digest) if digest else "empty: run `make pin-base`", bool(digest))
    mq = p.get("MOSQUITTO_DIGEST", "").removeprefix("sha256:")
    add("Mosquitto digest recorded", "set in pins.env",
        short(mq) if mq else "empty: run `make pin-mosquitto`", bool(mq))
    current = lockdoc.LOCK_DOC.read_text(encoding="utf-8") if lockdoc.LOCK_DOC.exists() else ""
    ok = current == lockdoc.render()
    add("versions.lock.md", "up to date", "current" if ok else "stale: run `make lock-doc`", ok)


# -------------------------------------------------------------------- main


def main() -> int:
    pins = load_pins()
    check_network()
    check_image(pins)
    check_installed_hashes()
    check_tools(pins)
    check_python()
    check_workspace(pins)
    check_grype_config()
    check_snapshots()
    check_vendored(pins)
    check_lockdoc(pins)

    table = Table(title="make doctor", title_style="bold", header_style="bold")
    table.add_column("Check")
    table.add_column("Expected")
    table.add_column("Actual")
    table.add_column("Result")
    style = {"PASS": "bold green", "FAIL": "bold red", "INFO": "cyan"}
    for c in CHECKS:
        table.add_row(escape(c.name), escape(c.expected), escape(c.actual),
                      f"[{style[c.result]}]{c.result}[/]")
    console.print(table)

    failed = [c for c in CHECKS if c.result == "FAIL"]
    OUT_DIR.mkdir(exist_ok=True)
    report = {"result": "FAIL" if failed else "PASS", "checks": [asdict(c) for c in CHECKS]}
    (OUT_DIR / "doctor.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failed:
        console.print(f"[bold red]DOCTOR FAIL[/] ({len(failed)} of {len(CHECKS)} checks)")
        return 1
    console.print(f"[bold green]DOCTOR PASS[/] ({len(CHECKS)} checks) -> out/doctor.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
