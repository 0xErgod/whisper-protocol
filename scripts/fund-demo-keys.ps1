$ErrorActionPreference = "Stop"

foreach ($alias in @("alice", "bob", "charlie")) {
    Write-Host "Requesting faucet funds for $alias"
    sui client faucet --address $alias
}
