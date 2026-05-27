# Publish the Whisper Move package to the shared dev devnet
# (`http://sui-devnet:9000` by convention) and write the resulting
# package id + registry id back into `networks.json`, then regenerate
# `packages/sdk/src/networks.ts`.
#
# Mirrors `.github/workflows/deploy-contract.yml` step-for-step (same
# `extract-publish-ids.py` + `update-networks-json.py`), but runs
# locally against an unfunded RPC. The devnet has no public faucet, so
# this script does not attempt to top up the active address — the
# caller is responsible for ensuring `sui client active-address` has
# gas on the target network.
#
# Usage:
#   ./scripts/deploy-devnet.ps1
#   ./scripts/deploy-devnet.ps1 -Rpc http://localhost:9000
#   ./scripts/deploy-devnet.ps1 -GasBudget 300000000
#
# Re-running is safe — every publish produces a fresh package id; the
# new id replaces the old one in networks.json and the SDK constants.

param(
    [string]$Rpc = "http://sui-devnet:9000",
    [string]$EnvAlias = "whisper-devnet",
    [string]$Network = "devnet",
    [int]$GasBudget = 200000000
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

function Require-Cmd($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "$name is not on PATH. Install it before running this script."
    }
}

Require-Cmd sui
Require-Cmd python
Require-Cmd pnpm
Require-Cmd cargo

# --- VK drift guard --------------------------------------------------------
#
# `contracts/sources/proofs.move` embeds each circuit's Groth16 verifying
# key as a `const VK_*: vector<u8>` byte array. Those bytes are deterministic
# given the trusted-setup seed pinned in `crates/prover-server/src/keys.rs`
# (and re-pinned in `crates/prover/src/bin/export-vks.rs`). If the Move
# source has drifted from what the seed would produce today — say, the
# circuit code changed — the on-chain verifier will reject every proof the
# prover-server emits, but the build still passes. The drift only surfaces
# end-to-end. We catch it here, before publish, by rebuilding the VKs and
# byte-diffing against the source.
#
# Comparison is on the extracted byte arrays only (the hex literals inside
# `const VK_*: vector<u8> = vector[ ... ];` blocks), not the surrounding
# text, so docstring or whitespace edits in proofs.move don't false-flag.

function Get-VkByteArrays {
    param([string]$Text)
    # Match `const NAME: vector<u8> = vector[ ... ];` blocks, capture the
    # name and the body. The body is whitespace + 0x.. literals + commas.
    $pattern = '(?ms)const\s+(VK_[A-Z0-9_]+)\s*:\s*vector<u8>\s*=\s*vector\[(.*?)\]\s*;'
    $matches = [regex]::Matches($Text, $pattern)
    $out = @{}
    foreach ($m in $matches) {
        $name = $m.Groups[1].Value
        $body = $m.Groups[2].Value
        # Pull every `0xXX` into a normalized hex stream so whitespace/comments
        # inside the body never affect the comparison.
        $bytes = [regex]::Matches($body, '0x[0-9a-fA-F]{2}') | ForEach-Object { $_.Value.ToLower() }
        $out[$name] = ($bytes -join ',')
    }
    return $out
}

Write-Host "==> rebuilding verifying keys to check for drift vs proofs.move"
$exportOut = cargo run --release --quiet --bin export-vks -p prover 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "export-vks failed; cannot validate VK drift. Re-run 'cargo build --release --bin export-vks -p prover' and inspect."
}
$exportText = ($exportOut -join "`n")

$proofsMovePath = Join-Path $repoRoot "contracts/sources/proofs.move"
if (-not (Test-Path $proofsMovePath)) {
    throw "proofs.move not found at $proofsMovePath"
}
$proofsSource = Get-Content $proofsMovePath -Raw

$expected = Get-VkByteArrays -Text $exportText
$actual   = Get-VkByteArrays -Text $proofsSource

if ($expected.Count -eq 0) { throw "export-vks produced no VK_* blocks; refusing to deploy" }

foreach ($name in $expected.Keys) {
    if (-not $actual.ContainsKey($name)) {
        throw "proofs.move is missing const ${name}. Regenerate via 'cargo run --release --bin export-vks -p prover' and paste the result."
    }
    if ($expected[$name] -ne $actual[$name]) {
        throw "VK drift detected for $name. The bytes in proofs.move do not match the seed-determined VK. Regenerate via 'cargo run --release --bin export-vks -p prover' and update proofs.move before deploying."
    }
    Write-Host "    $name OK ($(($expected[$name] -split ',').Count) bytes)"
}

foreach ($name in $actual.Keys) {
    if (-not $expected.ContainsKey($name)) {
        Write-Host "    WARN: proofs.move has $name but export-vks does not produce it. Stale constant?"
    }
}

Write-Host "==> ensuring sui client env '$EnvAlias' points at $Rpc"
# `sui client envs --json` returns a two-element array: the envs list,
# then the active alias. We only care about the list.
$envsJson = sui client envs --json 2>$null | ConvertFrom-Json
$envs = $envsJson[0]
$existing = $envs | Where-Object { $_.alias -eq $EnvAlias }
if (-not $existing) {
    sui client --yes new-env --alias $EnvAlias --rpc $Rpc | Out-Null
} elseif ($existing.rpc -ne $Rpc) {
    # `sui client new-env` refuses to overwrite an existing alias, so the
    # safe move is to surface the conflict to the caller rather than silently
    # diverge from the requested URL.
    throw "sui client env '$EnvAlias' is registered with rpc '$($existing.rpc)', expected '$Rpc'. Remove or rename it (sui client --yes new-env -a ...) before rerunning."
}
sui client switch --env $EnvAlias | Out-Null

$address = (sui client active-address).Trim()
Write-Host "==> active address: $address"

Write-Host "==> publishing contracts (gas budget $GasBudget)"
$outDir = Join-Path $repoRoot "out"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$publishRaw = Join-Path $outDir "publish-devnet.raw"
$publishErr = Join-Path $outDir "publish-devnet.err"
$contractsDir = Join-Path $repoRoot "contracts"

# Stderr stays in its own file so the JSON body in `$publishRaw` is never
# interleaved with progress lines. `extract-publish-ids.py` slices from the
# first `{`, and that heuristic only holds if stdout is JSON-only.
sui client publish $contractsDir --gas-budget $GasBudget --json `
    1> $publishRaw 2> $publishErr

if ($LASTEXITCODE -ne 0) {
    Write-Host "----- stderr -----"
    if (Test-Path $publishErr) { Get-Content $publishErr | Write-Host }
    throw "sui publish failed; stdout at $publishRaw, stderr at $publishErr"
}

Write-Host "==> extracting package + registry ids"
$idsRaw = python (Join-Path $repoRoot "scripts/ci/extract-publish-ids.py") $publishRaw
$ids = @{}
foreach ($line in $idsRaw -split "`n") {
    $line = $line.Trim()
    if (-not $line) { continue }
    $parts = $line -split "=", 2
    $ids[$parts[0]] = $parts[1]
}

$packageId  = $ids["package_id"]
$registryId = $ids["registry_id"]
$txDigest   = $ids["tx_digest"]

if (-not $packageId)  { throw "extract-publish-ids.py produced no package_id" }
if (-not $registryId) { throw "extract-publish-ids.py produced no registry_id" }
if (-not $txDigest)   { throw "extract-publish-ids.py produced no tx_digest" }

Write-Host "    package:  $packageId"
Write-Host "    registry: $registryId"
Write-Host "    tx:       $txDigest"

Write-Host "==> updating networks.json[$Network] and regenerating networks.ts"
$env:NETWORK = $Network
$env:PKG     = $packageId
$env:REG     = $registryId
$env:DIG     = $txDigest
$env:DEP     = $address

Push-Location $repoRoot
try {
    python (Join-Path $repoRoot "scripts/ci/update-networks-json.py")
    pnpm --filter "@whisper-protocol/sdk" run gen:networks
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Done. SDK constants now point at the freshly-published package."
Write-Host "Restart 'pnpm --filter @whisper-protocol/protocol dev' to pick them up."
