# Commit and push Aegis PoT API to GitHub
# Run from repo root: .\push-to-github.ps1
# Requires: Git installed and on PATH (https://git-scm.com/download/win)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot

Set-Location $repoRoot

if (-not (Test-Path .git)) {
    git init
    git branch -M main
}
git remote remove origin 2>$null
git remote add origin https://github.com/wijeratne-a/Aegis.git
git add -A
git status
git commit -m "Aegis PoT API: Rust axum backend, Python SDK, DeFi/Enterprise wedge tests"
git push -u origin main
