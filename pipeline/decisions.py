# SPDX-License-Identifier: Apache-2.0
"""Decision files: location, loading and validation (shared by queue, decide, vex, gate).

Layout: decisions/<release>/<board_dir>/<vuln_id>--<component>.yaml
Schema: schema/decision.schema.json (JSON Schema 2020-12, validated with jsonschema)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from pipeline.common import REPO

DECISIONS_DIR = REPO / "decisions"
SCHEMA_FILE = REPO / "schema" / "decision.schema.json"


@dataclass
class Decision:
    path: Path
    data: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def todo(self) -> str:
        """Short human summary of what is missing or wrong."""
        fields: list[str] = []
        for e in self.errors:
            where, _, msg = e.partition(": ")
            name = where.split("/")[0]
            if name == "(top level)" and "is a required property" in msg:
                name = msg.split("'")[1]
            if name not in fields:
                fields.append(name)
        return "to complete: " + ", ".join(fields) if fields else ""

    @property
    def rel(self) -> str:
        return str(self.path.relative_to(REPO))

    def get(self, *keys: str) -> Any:
        cur: Any = self.data
        for k in keys:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(k)
        return cur


def board_dir(board: str) -> str:
    return board.replace("/", "_")


def file_for(release: str, board: str, vuln_id: str, component: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", component)
    return DECISIONS_DIR / release / board_dir(board) / f"{vuln_id}--{safe}.yaml"


def _validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def load(path: Path, validator: jsonschema.Draft202012Validator | None = None) -> Decision:
    v = validator or _validator()
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return Decision(path, {}, [f"YAML error: {str(exc).splitlines()[0]}"])
    if not isinstance(data, dict):
        return Decision(path, {}, ["not a YAML mapping"])
    errors = []
    for e in sorted(v.iter_errors(data), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in e.absolute_path) or "(top level)"
        errors.append(f"{where}: {e.message}")
    return Decision(path, data, errors)


def load_all(root: Path = DECISIONS_DIR) -> list[Decision]:
    """Every decision file under decisions/ (all releases and boards)."""
    if not root.exists():
        return []
    v = _validator()
    return [load(p, v) for p in sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])]


def ids_of(d: Decision) -> set[str]:
    return {str(d.get("vuln_id")), *[str(a) for a in (d.get("aliases") or [])]}


def same_component(d: Decision, finding: dict[str, Any]) -> bool:
    if finding.get("component_purl"):
        return bool(d.get("component_purl") == finding["component_purl"])
    return bool(d.get("component") == finding["component"])


def covers(d: Decision, finding: dict[str, Any], product: dict[str, Any]) -> bool:
    """Valid decision for this finding AND bound to this exact product build."""
    return (d.valid and bool(ids_of(d) & {finding["id"], *finding.get("aliases", [])})
            and same_component(d, finding)
            and d.get("product", "version") == product["version"]
            and d.get("product", "firmware_sha256") == product["firmware_sha256"])
