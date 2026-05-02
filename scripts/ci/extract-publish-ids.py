#!/usr/bin/env python3
"""
Parse the JSON output of `sui client publish ... --json` and extract:
  - package_id  (the Move package's `published` object)
  - registry_id (the shared `KeyRegistry` created at publish time)
  - tx_digest   (the publish transaction's digest)

Usage:
  python3 scripts/ci/extract-publish-ids.py <publish.raw>

The CLI sometimes prepends non-JSON log lines before the actual JSON
body, so we forgive that by slicing from the first `{`. Outputs three
`KEY=VALUE` lines on stdout, suitable for `>> "$GITHUB_OUTPUT"`.

Exits non-zero with a clear message if any field is missing — easier
to debug than a `KeyError` traceback in CI logs.
"""
from __future__ import annotations

import json
import sys


def fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        fail("usage: extract-publish-ids.py <publish.raw>")

    try:
        with open(argv[1], "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as e:
        fail(f"could not read {argv[1]}: {e}")
        return  # unreachable, satisfies type checkers

    body_start = raw.find("{")
    if body_start < 0:
        fail("publish output contained no JSON body")

    try:
        data = json.loads(raw[body_start:])
    except json.JSONDecodeError as e:
        fail(f"publish output JSON did not parse: {e}")
        return

    changes = data.get("objectChanges") or []
    package_id = next(
        (c.get("packageId") for c in changes if c.get("type") == "published"),
        None,
    )
    if not package_id:
        fail("no `published` entry in objectChanges")

    registry_id = next(
        (
            c.get("objectId")
            for c in changes
            if (c.get("objectType") or "").endswith("::secret_sharing::KeyRegistry")
        ),
        None,
    )
    if not registry_id:
        fail("no KeyRegistry entry in objectChanges")

    digest = data.get("digest")
    if not digest:
        fail("publish response missing top-level digest")

    print(f"package_id={package_id}")
    print(f"registry_id={registry_id}")
    print(f"tx_digest={digest}")


if __name__ == "__main__":
    main(sys.argv)
