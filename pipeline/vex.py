# SPDX-License-Identifier: Apache-2.0
"""Build an OpenVEX document from the decisions for one firmware build.

  python -m pipeline.vex --out-dir out/v1.0/<board> --board <board> --version v1.0 [--sign]

Input:  decisions/<release>/<board>/*.yaml, out/<v>/<board>/normalized/firmware.spdx.json
Output: out/<v>/<board>/vex/firmware.openvex.json
        out/<v>/<board>/vex/firmware.openvex.sigstore.json   with --sign (cosign, offline)

Every decision file of this release and board must pass schema/decision.schema.json and
be bound to this firmware (version + SHA-256); otherwise nothing is written. Statements
are created with vexctl (create + add), one per decision, ordered by decided_at, with
SOURCE_DATE_EPOCH = decided_at so the document is reproducible from the same decisions.

Product: the firmware PURL with the purl-spec "checksum" qualifier carrying the
firmware SHA-256, e.g. pkg:generic/cra-evidence-demo-firmware@1.0.0?checksum=sha256:...
(vexctl has no flag for OpenVEX "hashes", the PURL qualifier carries the same binding).
Subcomponent: the component PURL, or its CPE when it has none (gcc).

The result is checked against the OpenVEX JSON schema (vendored, pinned in pins.env)
and parsed back with `vexctl merge`.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema
from rich.markup import escape
from rich.table import Table

from pipeline import decisions
from pipeline.common import REPO, console, load_pins, run, sha256_file
from pipeline.queue import classify

NORMALIZED = Path("normalized") / "firmware.spdx.json"
OPENVEX_SCHEMA = REPO / "schema" / "vendor" / "openvex_json_schema.json"
VEX_FILE = Path("vex") / "firmware.openvex.json"


class VexError(Exception):
    pass


def product_from_sbom(sbom_path: Path) -> dict[str, Any]:
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    root_id = next(r["relatedSpdxElement"] for r in sbom["relationships"]
                   if r["relationshipType"] == "DESCRIBES")
    root = next(p for p in sbom["packages"] if p["SPDXID"] == root_id)
    return {
        "name": root["name"], "version": root["versionInfo"],
        "purl": next(r["referenceLocator"] for r in root["externalRefs"] if r["referenceType"] == "purl"),
        "firmware_sha256": next(c["checksumValue"] for c in root["checksums"] if c["algorithm"] == "SHA256"),
        "author": str(root.get("supplier", "")).split(": ", 1)[-1] or "unknown",
    }


def status_note(d: decisions.Decision) -> str:
    ev = "; ".join(f"{e['type']}: {e['path_or_url']} ({e['description']})" for e in d.get("evidence"))
    note = f"Reviewed by {d.get('reviewer')}. Evidence: {ev}. Reassess if: {d.get('reassess_trigger')}."
    if d.get("status") == "under_investigation":
        note += f" Investigation due {d.get('due_date')}."
    return note


def vexctl_args(d: decisions.Decision, product_id: str) -> list[str]:
    args = ["--product", product_id, "--vuln", str(d.get("vuln_id")), "--status", str(d.get("status")),
            "--subcomponents", str(d.get("component_purl") or d.get("component_cpe")),
            "--status-note", status_note(d)]
    if d.get("aliases"):
        args += ["--aliases", ",".join(d.get("aliases"))]
    if d.get("status") == "not_affected":
        args += ["--justification", str(d.get("justification")),
                 "--impact-statement", str(d.get("impact_statement"))]
    if d.get("status") == "affected":
        args += ["--action-statement", str(d.get("action_statement"))]
    return args


def check_schema_pin() -> dict[str, Any]:
    pins = load_pins()
    if sha256_file(OPENVEX_SCHEMA) != pins["OPENVEX_SCHEMA_SHA256"]:
        raise VexError(f"{OPENVEX_SCHEMA.relative_to(REPO)} does not match OPENVEX_SCHEMA_SHA256")
    schema: dict[str, Any] = json.loads(OPENVEX_SCHEMA.read_text(encoding="utf-8"))
    return schema


def build(ds: list[decisions.Decision], product: dict[str, Any], doc_id: str, target: Path) -> dict[str, Any]:
    product_id = f"{product['purl']}?checksum=sha256:{product['firmware_sha256']}"
    ordered = sorted(ds, key=lambda d: (str(d.get("decided_at")), str(d.get("vuln_id")),
                                        str(d.get("component"))))
    with tempfile.TemporaryDirectory() as tmp:
        doc = Path(tmp) / "vex.json"
        for i, d in enumerate(ordered):
            env = {"SOURCE_DATE_EPOCH": str(d.get("decided_at"))}
            if i == 0:
                cmd = ["vexctl", "create", "--id", doc_id, "--author", product["author"],
                       "--file", str(doc), *vexctl_args(d, product_id)]
            else:
                cmd = ["vexctl", "add", "--in-place", "--document", str(doc), *vexctl_args(d, product_id)]
            res = run(cmd, env=env)
            if not res.ok:
                raise VexError(f"vexctl failed for {d.rel}: {res.stderr.strip()[-300:]}")
        text = doc.read_text(encoding="utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    vex: dict[str, Any] = json.loads(text)
    return vex


def verify(vex_path: Path, schema: dict[str, Any], expected: int) -> None:
    vex = json.loads(vex_path.read_text(encoding="utf-8"))
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(vex))
    if errors:
        raise VexError(f"OpenVEX schema: {errors[0].message[:200]}")
    res = run(["vexctl", "merge", "--id", "roundtrip", str(vex_path)])
    if not res.ok:
        raise VexError(f"vexctl could not parse the document: {res.stderr.strip()[-300:]}")
    merged = json.loads(res.stdout)
    if len(merged.get("statements", [])) != expected or len(vex["statements"]) != expected:
        raise VexError("statement count changed in vexctl round trip")


def sign(vex_path: Path) -> Path:
    bundle = vex_path.with_name("firmware.openvex.sigstore.json")
    key = REPO / "keys" / "cosign.key"
    if not key.exists():
        raise VexError("keys/cosign.key missing: run make keys")
    res = run(["cosign", "sign-blob", "--key", str(key), "--bundle", str(bundle),
               "--use-signing-config=false", "--tlog-upload=false", "--yes", str(vex_path)])
    if not res.ok:
        raise VexError(f"cosign sign-blob failed: {res.stderr.strip()[-300:]}")
    res = run(["cosign", "verify-blob", "--key", str(REPO / "keys" / "cosign.pub"), "--bundle",
               str(bundle), "--insecure-ignore-tlog=true", str(vex_path)])
    if not res.ok:
        raise VexError(f"cosign verify-blob failed: {res.stderr.strip()[-300:]}")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sign", action="store_true")
    args = parser.parse_args(argv)

    target = args.out_dir / VEX_FILE
    for stale in (target, target.with_name("firmware.openvex.sigstore.json")):
        stale.unlink(missing_ok=True)
    sbom_path = args.out_dir / NORMALIZED
    if not sbom_path.exists():
        console.print(f"[bold red]{sbom_path} missing: run make normalize first[/]")
        return 1
    product = product_from_sbom(sbom_path)
    folder = decisions.DECISIONS_DIR / args.version / decisions.board_dir(args.board)
    ds = [decisions.load(p) for p in sorted(folder.glob("*.yaml"))] if folder.exists() else []

    problems: list[tuple[str, str]] = []
    for d in ds:
        if not d.valid:
            problems.append((d.path.name, d.todo))
        elif (d.get("product", "firmware_sha256") != product["firmware_sha256"]
              or d.get("product", "version") != product["version"]):
            problems.append((d.path.name, "bound to another firmware: "
                             f"{d.get('product', 'version')} {str(d.get('product', 'firmware_sha256'))[:12]}"))
    if problems:
        t = Table(title=f"make vex  |  {args.version}  |  {args.board}  |  not built")
        t.add_column("Decision file", no_wrap=True)
        t.add_column("Problem")
        for name, msg in problems[:15]:
            t.add_row(escape(name), escape(msg[:90]))
        console.print(t)
        console.print(f"[bold red]{len(problems)} of {len(ds)} decision files are drafts or stale; "
                      "no VEX written[/] (make queue shows what is open)")
        return 1
    if not ds:
        console.print(f"[bold red]no decisions in {folder.relative_to(REPO)}: run make decide[/]")
        return 1

    doc_id = (f"https://cra-evidence-demo.invalid/vex/{args.version}/"
              f"{decisions.board_dir(args.board)}/{product['firmware_sha256'][:16]}")
    try:
        schema = check_schema_pin()
        vex = build(ds, product, doc_id, target)
        verify(target, schema, len(ds))
        bundle = sign(target) if args.sign else None
    except VexError as exc:
        target.unlink(missing_ok=True)
        console.print(f"[bold red]vex: {escape(str(exc))}[/]")
        return 1

    t = Table(title=f"OpenVEX  |  {args.version}  |  {args.board}  |  firmware "
                    f"{product['firmware_sha256'][:12]}")
    for col in ("Vulnerability", "Component", "Status", "Justification", "Reviewer"):
        t.add_column(col, no_wrap=True)
    by_key = {(str(d.get("vuln_id")), str(d.get("component_purl") or d.get("component_cpe"))): d for d in ds}
    for s in vex["statements"][:10]:
        sub = s["products"][0].get("subcomponents", [{}])[0].get("@id", "")
        dec = by_key.get((s["vulnerability"]["name"], sub))
        t.add_row(s["vulnerability"]["name"], str(dec.get("component")) if dec else sub[:20],
                  s["status"], s.get("justification", "-"), str(dec.get("reviewer")) if dec else "?")
    console.print(t)
    if len(vex["statements"]) > 10:
        console.print(f"(first 10 of {len(vex['statements'])} statements shown)")
    counts: dict[str, int] = {}
    for s in vex["statements"]:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    console.print(f"{len(vex['statements'])} statements ("
                  + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
                  + f") -> {target}; OpenVEX schema + vexctl round trip OK")
    if bundle:
        console.print(f"signed (cosign, offline): {bundle.name}, verified with keys/cosign.pub")
    findings_path = args.out_dir / "findings.json"
    if findings_path.exists():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        if findings["product"]["firmware_sha256"] == product["firmware_sha256"]:
            still_open = classify(findings, decisions.load_all())
            if still_open:
                console.print(f"[yellow]{len(still_open)} findings of the last scan have no decision "
                              "yet (make queue)[/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
