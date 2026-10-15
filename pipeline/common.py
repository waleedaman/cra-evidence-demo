# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the pipeline scripts: paths, pins, hashing, subprocess, output."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

REPO = Path(__file__).resolve().parents[1]
PINS_FILE = REPO / "pins.env"
REQUIREMENTS_LOCK = REPO / "requirements.lock"
SNAPSHOTS_FILE = REPO / "vulndb" / "snapshots.yaml"
OSV_ECOSYSTEMS_FILE = REPO / "vulndb" / "osv-ecosystems.txt"
ARCHIVE_DIR = REPO / "vulndb" / "archives"
GRYPE_CONFIG = REPO / "config" / "grype.yaml"
OUT_DIR = REPO / "out"

# Inside the image the west workspace is /ws and caches live in the volume.
WORKSPACE = Path(os.environ.get("CRA_WORKSPACE", "/ws"))
CACHE_DIR = Path(os.environ.get("CRA_CACHE_DIR", str(WORKSPACE / "cache")))

# Large-font friendly console: no emoji, fixed width for projector use.
console = Console(width=int(os.environ.get("CRA_WIDTH", "100")), emoji=False, highlight=False)


def load_pins(path: Path = PINS_FILE) -> dict[str, str]:
    """Parse pins.env (KEY=VALUE lines, '#' comments)."""
    pins: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path.name}:{lineno}: expected KEY=VALUE, got {raw!r}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z0-9_]+", key) or " " in value:
            raise ValueError(f"{path.name}:{lineno}: invalid entry {raw!r}")
        pins[key] = value
    return pins


_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def load_requirements(path: Path = REQUIREMENTS_LOCK) -> dict[str, str]:
    """Return {normalized-name: version} from a hashed requirements.lock."""
    reqs: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _REQ_LINE.match(line)
        if m:
            reqs[normalize_dist_name(m.group(1))] = m.group(2)
    return reqs


def normalize_dist_name(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None,
        timeout: float = 120.0) -> CmdResult:
    """Run a command and capture its output. Missing executables become rc=127."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=full_env, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return CmdResult(127, "", str(exc))
    except subprocess.TimeoutExpired:
        return CmdResult(124, "", f"timeout after {timeout}s: {' '.join(cmd)}")
    return CmdResult(proc.returncode, proc.stdout, proc.stderr)
