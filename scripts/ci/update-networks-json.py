#!/usr/bin/env python3
"""
Update one network entry in `networks.json` after a contract deploy.

Reads the entry's existing `rpcUrl` and `note` (so they're preserved)
and overwrites the deploy-specific fields with the values supplied
via env vars.

Usage:
  NETWORK=testnet \
  PKG=0x... REG=0x... DIG=... DEP=0x... \
  python3 scripts/ci/update-networks-json.py

Run from the repo root. Emits to stderr on missing env vars; the
script is small enough to test offline by setting the four env vars
in a shell.

Pairs with packages/sdk/scripts/generate-networks.mjs — after this
script writes networks.json, the workflow runs that generator to
keep packages/sdk/src/networks.ts in sync.
"""
from __future__ import annotations

import json
import os
import sys
import time


def env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"::error::missing required env var {name}", file=sys.stderr)
        sys.exit(1)
    return value


def main() -> None:
    network = env_required("NETWORK")
    pkg = env_required("PKG")
    reg = env_required("REG")
    dig = env_required("DIG")
    dep = env_required("DEP")

    path = "networks.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as e:
        print(f"::error::could not read {path}: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"::error::{path} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    networks = data.get("networks") or {}
    existing = networks.get(network) or {}
    rpc_url = existing.get("rpcUrl")
    if not rpc_url:
        print(
            f"::error::networks.json has no entry (or no rpcUrl) for '{network}'",
            file=sys.stderr,
        )
        sys.exit(1)

    networks[network] = {
        "rpcUrl": rpc_url,
        "packageId": pkg,
        "registryId": reg,
        "deployedAtMs": int(time.time() * 1000),
        "deployer": dep,
        "txDigest": dig,
        "note": existing.get("note"),
    }
    data["networks"] = networks

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")

    print(f"updated {path} for network={network}")


if __name__ == "__main__":
    main()
