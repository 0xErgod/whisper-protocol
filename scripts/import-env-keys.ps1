$ErrorActionPreference = "Stop"

if (!(Test-Path .env)) {
    throw "Missing .env. Run: cargo run -q -- generate-env > .env"
}

$existing = sui keytool list | Out-String
$lines = Get-Content .env | Where-Object { $_ -match '^[A-Z]+_ED25519_PRIVATE_KEY=' }

foreach ($line in $lines) {
    $parts = $line -split '=', 2
    $alias = ($parts[0] -replace '_ED25519_PRIVATE_KEY', '').ToLower()
    $hex = $parts[1].Trim()

    if ($existing -match "\b$alias\b") {
        Write-Host "Skipping existing alias $alias"
        continue
    }

    $converted = sui keytool convert $hex --json | ConvertFrom-Json
    sui keytool import $converted.bech32WithFlag ed25519 --alias $alias
}
