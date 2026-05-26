#!/usr/bin/env node
// Generate `packages/sdk/src/networks.ts` from the repo-root
// `networks.json`. Run as `pnpm --filter @whisper-protocol/sdk run
// gen:networks`, which is wired into the package's `prebuild` so npm
// publishes always carry the freshest IDs.
//
// Two modes:
//   default          — write the file
//   --check          — exit non-zero if the on-disk file would differ.
//                      CI uses this to fail builds when networks.ts has
//                      drifted from networks.json.
//
// Source of truth:  /networks.json   (root)
// Generated file:   packages/sdk/src/networks.ts

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const SOURCE_JSON = resolve(REPO_ROOT, "networks.json");
const TARGET_TS = resolve(__dirname, "..", "src", "networks.ts");

function loadNetworks() {
  const raw = readFileSync(SOURCE_JSON, "utf8");
  const data = JSON.parse(raw);
  if (!data || typeof data.networks !== "object") {
    throw new Error(`networks.json is missing the 'networks' object`);
  }
  return data.networks;
}

function tsLiteral(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  throw new Error(`unsupported value type for ts emit: ${typeof value}`);
}

function renderNetwork(name, entry) {
  const label = name.toUpperCase();
  const pkgId = tsLiteral(entry.packageId ?? null);
  const regId = tsLiteral(entry.registryId ?? null);
  const rpc = tsLiteral(entry.rpcUrl);
  const note = entry.note ? tsLiteral(entry.note) : undefined;
  const lines = [
    `export const ${label}: NetworkConfig = {`,
    `  rpcUrl: ${rpc},`,
    `  packageId: ${pkgId},`,
    `  registryId: ${regId},`,
  ];
  if (note !== undefined) {
    lines.push(`  note: ${note},`);
  }
  lines.push("};");
  return lines.join("\n");
}

function render(networks) {
  const order = ["localnet", "devnet", "testnet", "mainnet"].filter((n) => networks[n]);
  const blocks = order.map((n) => renderNetwork(n, networks[n]));

  const networksMap = order.map((n) => `  ${n}: ${n.toUpperCase()},`).join("\n");

  return [
    "// AUTO-GENERATED FROM /networks.json. DO NOT EDIT BY HAND.",
    "//",
    "// Update via:",
    "//     pnpm --filter @whisper-protocol/sdk run gen:networks",
    "//",
    "// CI rejects pushes where this file has drifted from networks.json",
    "// — see scripts/generate-networks.mjs --check.",
    "",
    "export interface NetworkConfig {",
    "  rpcUrl: string;",
    "  packageId: string | null;",
    "  registryId: string | null;",
    "  note?: string;",
    "}",
    "",
    ...blocks.flatMap((b) => [b, ""]),
    `export const NETWORKS = {`,
    networksMap,
    `} as const;`,
    "",
    "export type NetworkName = keyof typeof NETWORKS;",
    "",
  ].join("\n");
}

function main() {
  const check = process.argv.includes("--check");
  const networks = loadNetworks();
  const generated = render(networks);

  if (check) {
    let onDisk = "";
    try {
      onDisk = readFileSync(TARGET_TS, "utf8");
    } catch (e) {
      console.error(`networks.ts not found at ${TARGET_TS}`);
      process.exit(1);
    }
    if (onDisk.replace(/\r\n/g, "\n") !== generated.replace(/\r\n/g, "\n")) {
      console.error(
        "networks.ts is out of sync with networks.json.\n" +
          "Run: pnpm --filter @whisper-protocol/sdk run gen:networks\n" +
          "and commit the result.",
      );
      process.exit(1);
    }
    console.log("networks.ts is in sync with networks.json.");
    return;
  }

  writeFileSync(TARGET_TS, generated);
  console.log(`wrote ${TARGET_TS}`);
}

main();
