param(
    [Parameter(Mandatory = $true)]
    [string]$EndstoneSource
)

$ErrorActionPreference = "Stop"
$expectedCommit = "39f5935f2662f2a063f79f9a2502e0f029d0e4e0"
$source = (Resolve-Path -LiteralPath $EndstoneSource).Path
$patch = Join-Path $PSScriptRoot "patches\endstone-pre-login-identity.patch"
$actualCommit = (git -C $source rev-parse HEAD).Trim()

if ($actualCommit -ne $expectedCommit) {
    throw "Expected Endstone $expectedCommit, found $actualCommit. Rebase and revalidate the patch before applying it."
}

git -C $source apply --check $patch
if ($LASTEXITCODE -ne 0) {
    throw "The Endstone patch does not apply cleanly to $source."
}

git -C $source apply $patch
if ($LASTEXITCODE -ne 0) {
    throw "Failed to apply the Endstone patch to $source."
}

Write-Host "Applied the pre-login identity patch to $source"
