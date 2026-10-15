# SPDX-License-Identifier: Apache-2.0
"""Read and write SPDX 2.x documents with spdx-tools (one shared place for the workaround).

Workaround: spdx-tools 0.8.5 (latest release) builds a new license-expression parser for
every license expression it reads from a *tag-value* file
(spdx_tools/spdx/parser/tagvalue/parser.py, p_license -> get_spdx_licensing()). Each
build loads the full license index (~27 ms). zephyr.spdx has ~2000 expressions, so
parsing it took ~53 s. The JSON and RDF parsers already use one shared, cached instance
(spdx_tools.common.spdx_licensing.spdx_licensing). We point the tag-value parser at that
same instance. Same license index, same result: the parsed zephyr.spdx converted to JSON
is byte-identical with and without the workaround (checked, see docs/sbom-quality.md).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.parser.tagvalue import parser as _tagvalue_parser
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage
from spdx_tools.spdx.writer.write_anything import write_file

_PATCHED = False


def use_shared_licensing() -> None:
    """Apply the tag-value parser workaround described in the module docstring (idempotent)."""
    global _PATCHED
    if not _PATCHED:
        setattr(_tagvalue_parser, "get_spdx_licensing", lambda: spdx_licensing)
        _PATCHED = True


def parse(path: Path) -> Document:
    """Parse an SPDX 2.x document (tag-value, JSON, ...; format from the file name)."""
    use_shared_licensing()
    doc: Any = parse_file(str(path))
    assert isinstance(doc, Document)
    return doc


def validate(doc: Document) -> list[str]:
    """spdx-tools validation against the document's own SPDX version. Empty list = valid."""
    messages: list[ValidationMessage] = validate_full_spdx_document(doc)
    return [str(m.validation_message) for m in messages]


def license(expression: str) -> Any:
    """Parse an SPDX license expression with the shared licensing instance."""
    return spdx_licensing.parse(expression)


def write_json(doc: Document, path: Path) -> None:
    """Write SPDX JSON; spdx-tools validates first and raises ValueError if invalid."""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_file(doc, str(path), validate=True)
