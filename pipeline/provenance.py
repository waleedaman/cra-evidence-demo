# SPDX-License-Identifier: Apache-2.0
"""Build provenance: in-toto Statement v1 with a SLSA Provenance v1 predicate.

  generate  write out/<version>/<board>/provenance.intoto.json (unsigned statement)
  verify    check the signed bundle offline with cosign, then check the *signed*
            statement against pins.env and the files on disk

Signing itself is done by `cosign attest-blob` in the Makefile (offline, local key).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from rich.markup import escape
from rich.table import Table

from pipeline.common import REPO, console, load_pins, run, sha256_file

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
# Our own identifiers. ".invalid" is a reserved TLD: these name things, they are not URLs
# to fetch. docs/provenance.md describes what they mean.
BUILD_TYPE = "https://cra-evidence-demo.invalid/buildtypes/zephyr-west-docker/v1"
BUILDER_ID = "https://cra-evidence-demo.invalid/builders/local-docker/v1"
STATEMENT_FILE = "provenance.intoto.json"
OUT_ROOT = "out"
BUNDLE_FILE = "provenance.sigstore.json"
GH = "https://github.com"
BUILD_ROOT = Path(os.environ.get("CRA_BUILD_ROOT", "/ws/build"))


def board_dir(board: str) -> str:
    return board.replace("/", "_")


def git_out(*args: str) -> str:
    res = run(["git", "-C", str(REPO), *args])
    return res.stdout.strip() if res.ok else ""


def mtime_utc(path: Path) -> str:
    ts = datetime.fromtimestamp(path.stat().st_mtime, UTC).replace(microsecond=0)
    return ts.isoformat().replace("+00:00", "Z")


def cmake_cache(build_dir: Path) -> dict[str, str]:
    cache: dict[str, str] = {}
    f = build_dir / "CMakeCache.txt"
    if f.exists():
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^([A-Za-z0-9_]+):[A-Z]+=(.*)$", line)
            if m:
                cache[m.group(1)] = m.group(2)
    return cache


def compiler_version(cache: dict[str, str]) -> str:
    cc = cache.get("CMAKE_C_COMPILER", "")
    res = run([cc, "--version"]) if cc else None
    return res.stdout.splitlines()[0] if res and res.ok and res.stdout else "unknown"


# ------------------------------------------------------------------ generate


def subjects(out_dir: Path) -> list[dict[str, Any]]:
    """Firmware artifacts (from artifacts.json) plus the SPDX documents."""
    meta = json.loads((out_dir / "artifacts.json").read_text(encoding="utf-8"))
    subs: list[dict[str, Any]] = []
    for name in meta["artifacts"]:
        subs.append({"name": name, "digest": {"sha256": sha256_file(out_dir / name)}})
    for spdx in sorted((out_dir / "sbom").glob("*.spdx")):
        subs.append({"name": f"sbom/{spdx.name}", "digest": {"sha256": sha256_file(spdx)}})
    return subs


def resolved_dependencies(build_dir: Path, pins: dict[str, str]) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    head = git_out("rev-parse", "HEAD")
    if head:
        deps.append({"name": "source:cra-evidence-demo", "uri": "git+file:///ws/demo",
                     "digest": {"gitCommit": head}})

    meta = yaml.safe_load((build_dir / "zephyr" / "zephyr.meta").read_text(encoding="utf-8"))
    z = meta["zephyr"]
    deps.append({"name": "zephyr", "uri": f"git+{z['remote']}@{z['revision']}",
                 "digest": {"gitCommit": z["revision"]},
                 "annotations": {"tags": z.get("tags") or []}})
    for mod in meta.get("modules", []):
        dep: dict[str, Any] = {"name": f"module:{mod['name']}",
                               "uri": f"git+{mod.get('remote', 'unknown')}@{mod['revision']}",
                               "digest": {"gitCommit": mod["revision"]}}
        refs = (mod.get("security") or {}).get("external-references") or []
        if refs:
            dep["annotations"] = {"external-references": refs}
        deps.append(dep)

    base = pins["CI_BASE_DIGEST"].removeprefix("sha256:")
    deps.append({"name": "image:ci-base",
                 "uri": f"pkg:docker/{pins['CI_BASE_IMAGE'].split('/', 1)[1]}@{pins['CI_BASE_TAG']}"
                        f"?repository_url={pins['CI_BASE_IMAGE'].split('/', 1)[0]}",
                 "digest": {"sha256": base}})
    sdk = pins["ZEPHYR_SDK_VERSION"]
    sdk_url = f"{GH}/zephyrproject-rtos/sdk-ng/releases/download/v{sdk}"
    deps.append({"name": "zephyr-sdk-minimal",
                 "uri": f"{sdk_url}/zephyr-sdk-{sdk}_linux-x86_64_minimal.tar.xz",
                 "digest": {"sha256": pins["ZEPHYR_SDK_MINIMAL_SHA256"]}})
    deps.append({"name": "zephyr-sdk-arm-zephyr-eabi",
                 "uri": f"{sdk_url}/toolchain_gnu_linux-x86_64_arm-zephyr-eabi.tar.xz",
                 "digest": {"sha256": pins["ZEPHYR_SDK_ARM_SHA256"]}})
    ca = REPO / "certs" / "generated" / "demo-ca.der"
    if ca.exists():
        deps.append({"name": "demo-ca.der (embedded trust anchor)", "uri": "file:certs/generated/demo-ca.der",
                     "digest": {"sha256": sha256_file(ca)}})
    return deps


def cmd_generate(version: str, board: str) -> int:
    pins = load_pins()
    out_dir = REPO / OUT_ROOT / version / board_dir(board)
    build_dir = BUILD_ROOT / version / board_dir(board)
    for need in (out_dir / "artifacts.json", out_dir / "sbom" / "build.spdx",
                 build_dir / "zephyr" / "zephyr.meta"):
        if not need.exists():
            console.print(f"[bold red]missing {need}[/]: run make build and make sbom first")
            return 1
    cache = cmake_cache(build_dir)
    dirty = bool(git_out("status", "--porcelain", "--untracked-files=no"))
    image_id = os.environ.get("CRA_IMAGE_ID", "").removeprefix("sha256:")
    subs = subjects(out_dir)
    invocation = f"{version}/{board_dir(board)}/{subs[0]['digest']['sha256'][:16]}"
    statement: dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": subs,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "version": version,
                    "board": board,
                    "application": "app",
                    "manifest": "west.yml",
                    "sourceDirty": dirty,
                },
                "internalParameters": {
                    "zephyrToolchainVariant": cache.get("ZEPHYR_TOOLCHAIN_VARIANT", ""),
                    "compiler": compiler_version(cache),
                    "kconfigSha256": sha256_file(build_dir / "zephyr" / ".config"),
                    "buildDirectory": str(build_dir),
                },
                "resolvedDependencies": resolved_dependencies(build_dir, pins),
            },
            "runDetails": {
                "builder": {
                    "id": BUILDER_ID,
                    "version": {"cra-evidence-demo-image": f"sha256:{image_id}" if image_id else "unknown"},
                    "builderDependencies": [
                        {"name": "image:cra-evidence-demo (local build, not pushed)",
                         "digest": {"sha256": image_id or "unknown"}},
                    ],
                },
                "metadata": {
                    "invocationId": invocation,
                    "finishedOn": mtime_utc(out_dir / "artifacts.json"),
                },
            },
        },
    }
    (out_dir / STATEMENT_FILE).write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8")
    console.print(f"statement: {len(statement['subject'])} subjects, "
                  f"{len(statement['predicate']['buildDefinition']['resolvedDependencies'])} dependencies"
                  f"{' [bold red](source tree dirty)[/]' if dirty else ''}")
    return 0


# -------------------------------------------------------------------- verify


def signed_statement(bundle: Path) -> dict[str, Any]:
    env = json.loads(bundle.read_text(encoding="utf-8"))["dsseEnvelope"]
    payload: dict[str, Any] = json.loads(base64.b64decode(env["payload"]))
    return payload


def verify_rows(out_dir: Path, pubkey: Path) -> list[tuple[str, str, bool]]:
    """All provenance checks for one build directory (used by make verify and the gate)."""
    pins = load_pins()
    bundle = out_dir / BUNDLE_FILE
    if not bundle.exists():
        return [("signed provenance present", f"missing {bundle.name}", False)]
    rows: list[tuple[str, str, bool]] = []

    # 1. signature + subject digest, per firmware artifact, by cosign (offline: no tlog)
    st = signed_statement(bundle)
    for sub in st["subject"]:
        f = out_dir / sub["name"]
        if sub["name"].startswith("sbom/"):
            continue
        res = run(["cosign", "verify-blob-attestation", "--key", str(pubkey), "--bundle", str(bundle),
                   "--type", "slsaprovenance1", "--insecure-ignore-tlog=true", str(f)])
        rows.append((f"signature + digest: {sub['name']}", "Verified OK" if res.ok else
                     (res.stderr.strip().splitlines() or ["failed"])[-1][-60:], res.ok))
    # SBOM documents: digest check against the signed statement
    sbom_bad = [s["name"] for s in st["subject"] if s["name"].startswith("sbom/")
                and (not (out_dir / s["name"]).exists()
                     or sha256_file(out_dir / s["name"]) != s["digest"]["sha256"])]
    n_sbom = sum(1 for s in st["subject"] if s["name"].startswith("sbom/"))
    rows.append((f"SBOM documents ({n_sbom}) match signed digests",
                 "match" if not sbom_bad else "changed: " + ", ".join(sbom_bad), not sbom_bad))

    # 2. the signed statement against the pins
    bd = st["predicate"]["buildDefinition"]
    deps = {d["name"]: d for d in bd["resolvedDependencies"]}
    zc = deps.get("zephyr", {}).get("digest", {}).get("gitCommit", "")
    rows.append(("zephyr commit = pins.env", zc[:12] or "-", zc == pins["ZEPHYR_COMMIT"]))
    bad_mods = []
    for key, value in pins.items():
        if key.startswith("MODULE_") and key.endswith("_SHA"):
            name = key.removeprefix("MODULE_").removesuffix("_SHA").lower()
            match = [d for n, d in deps.items()
                     if n.startswith("module:") and n[7:].replace("-", "_") == name]
            if not match or match[0]["digest"]["gitCommit"] != value:
                bad_mods.append(name)
    rows.append(("module commits = pins.env", "match" if not bad_mods else ", ".join(bad_mods),
                 not bad_mods))
    base = deps.get("image:ci-base", {}).get("digest", {}).get("sha256", "")
    rows.append(("ci-base digest = pins.env", base[:12] or "-",
                 base == pins["CI_BASE_DIGEST"].removeprefix("sha256:")))
    sdk = deps.get("zephyr-sdk-minimal", {}).get("digest", {}).get("sha256", "")
    rows.append(("Zephyr SDK archive = pins.env", sdk[:12] or "-", sdk == pins["ZEPHYR_SDK_MINIMAL_SHA256"]))
    dirty = bool(bd["externalParameters"].get("sourceDirty"))
    rows.append(("built from committed source", "dirty tree" if dirty else "clean", not dirty))
    return rows


def cmd_verify(version: str, board: str, pubkey: Path) -> int:
    out_dir = REPO / OUT_ROOT / version / board_dir(board)
    if not (out_dir / BUNDLE_FILE).exists():
        console.print(f"[bold red]missing {out_dir / BUNDLE_FILE}[/]: run make provenance first")
        return 1
    rows = verify_rows(out_dir, pubkey)
    table = Table(title=f"make verify  |  {version}  {board}")
    table.add_column("Check")
    table.add_column("Actual")
    table.add_column("Result")
    for name, actual, ok in rows:
        table.add_row(escape(name), escape(actual), "[bold green]PASS[/]" if ok else "[bold red]FAIL[/]")
    console.print(table)
    failed = [r for r in rows if not r[2]]
    (out_dir / "verify.json").write_text(json.dumps(
        {"result": "FAIL" if failed else "PASS",
         "checks": [{"check": n, "actual": a, "ok": ok} for n, a, ok in rows]}, indent=2) + "\n",
        encoding="utf-8")
    return 1 if failed else 0


def cmd_summary(version: str, board: str) -> int:
    out_dir = REPO / OUT_ROOT / version / board_dir(board)
    st = signed_statement(out_dir / BUNDLE_FILE)
    table = Table(title=f"Signed provenance  |  {version}  {board}")
    table.add_column("Subject")
    table.add_column("sha256")
    for s in st["subject"]:
        table.add_row(s["name"], s["digest"]["sha256"][:16] + "...")
    console.print(table)
    deps = st["predicate"]["buildDefinition"]["resolvedDependencies"]
    console.print(f"{len(deps)} resolved dependencies, builder image "
                  f"{st['predicate']['runDetails']['builder']['version']['cra-evidence-demo-image'][:19]}...")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("generate", "verify", "summary"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--pubkey", type=Path, default=REPO / "keys" / "cosign.pub")
    parser.add_argument("--out-root", default="out", help="results root (default: out)")
    args = parser.parse_args(argv)
    global OUT_ROOT
    OUT_ROOT = args.out_root
    if args.command == "generate":
        return cmd_generate(args.version, args.board)
    if args.command == "summary":
        return cmd_summary(args.version, args.board)
    return cmd_verify(args.version, args.board, args.pubkey)


if __name__ == "__main__":
    sys.exit(main())
