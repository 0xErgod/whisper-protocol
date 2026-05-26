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

Write-Host "==> ensuring sui client env '$EnvAlias' points at $Rpc"
$envList = sui client envs --json 2>$null | ConvertFrom-Json
$existing = $envList | Where-Object { $_.alias -eq $EnvAlias }
if (-not $existing) {
    sui client --yes new-env --alias $EnvAlias --rpc $Rpc | Out-Null
} elseif ($existing.rpc -ne $Rpc) {
    Write-Host "    existing env '$EnvAlias' has rpc '$($existing.rpc)'; updating"
    sui client --yes new-env --alias $EnvAlias --rpc $Rpc | Out-Null
}
sui client switch --env $EnvAlias | Out-Null

$address = (sui client active-address).Trim()
Write-Host "==> active address: $address"

Write-Host "==> publishing contracts (gas budget $GasBudget)"
$outDir = Join-Path $repoRoot "out"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$publishRaw = Join-Path $outDir "publish-devnet.raw"
$contractsDir = Join-Path $repoRoot "contracts"

sui client publish $contractsDir --gas-budget $GasBudget --json 2>&1 |
    Tee-Object -FilePath $publishRaw

if ($LASTEXITCODE -ne 0) {
    throw "sui publish failed; full output captured at $publishRaw"
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
