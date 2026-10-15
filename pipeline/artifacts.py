# SPDX-License-Identifier: Apache-2.0
"""Copy firmware artifacts from a Zephyr build directory into out/ and summarize them.

  python -m pipeline.artifacts --build-dir /ws/build/v1.0/<board> --out-dir out/v1.0/<board>
                               --board <board> --version v1.0
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from rich.table import Table

from pipeline.common import console, sha256_file

# Files we treat as release artifacts, in display order. Only existing ones are copied.
ARTIFACTS = ("zephyr.exe", "zephyr.elf", "zephyr.uf2", "zephyr.hex", "zephyr.bin")
# Build evidence kept next to the artifacts (used by later phases).
EVIDENCE = (".config", "zephyr.map", "zephyr.dts", "zephyr.meta")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--quiet", action="store_true", help="do not print the table")
    args = parser.parse_args(argv)

    src = args.build_dir / "zephyr"
    out: Path = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    table = Table(title=f"Firmware {args.version}  |  {args.board}")
    table.add_column("Artifact")
    table.add_column("Size", justify="right")
    table.add_column("sha256")
    record: dict[str, dict[str, object]] = {}
    for name in ARTIFACTS:
        f = src / name
        if not f.exists():
            continue
        shutil.copy2(f, out / name)
        digest = sha256_file(out / name)
        size = (out / name).stat().st_size
        record[name] = {"sha256": digest, "size": size}
        table.add_row(name, f"{size:,}", digest[:16] + "...")
    for name in EVIDENCE:
        f = src / name
        if f.exists():
            shutil.copy2(f, out / name.lstrip("."))
    if not record:
        console.print(f"[bold red]no artifacts found in {src}[/]")
        return 1
    (out / "artifacts.json").write_text(
        json.dumps({"version": args.version, "board": args.board, "artifacts": record},
                   indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        console.print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
