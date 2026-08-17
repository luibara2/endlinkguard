# Builds EndlinkGuard.jar, the Geyser build of EndlinkGuard.
#
#     .\build.ps1 -GeyserJar <path-to-Geyser.jar>
#     .\build.ps1 -GeyserJar <...> -DeployTo <server>\extensions
#
# -GeyserJar is whichever Geyser this will run on: Geyser-Standalone.jar,
# Geyser-Spigot.jar, Geyser-Velocity.jar and so on. Extensions themselves are
# platform-agnostic, but this one makes a single call into Geyser's internals to
# set a player's forwarded address, and that is not version-agnostic -- so build
# against the jar it will actually load into. See README.md.
#
# Restart Geyser afterwards; extensions load at startup only.
#
# There is deliberately no Gradle and no dependency resolution. Every Geyser jar
# already carries the whole extension API, so compiling against it needs nothing
# from the network and cannot break on a dependency mirror or a TLS-intercepting
# machine.
#
# Requires a JDK 21+ on PATH.

param(
    [Parameter(Mandatory = $true)][string]$GeyserJar,
    [string]$DeployTo,
    [switch]$NoDeploy
)

$ErrorActionPreference = "Stop"

$project = $PSScriptRoot
$src     = Join-Path $project "src\main\java"
$res     = Join-Path $project "src\main\resources"
$build   = Join-Path $project "build"
$dist    = Join-Path $project "dist"
$out     = Join-Path $dist "EndlinkGuard.jar"

if (-not (Test-Path $GeyserJar)) {
    throw "no Geyser jar at $GeyserJar"
}
$GeyserJar = (Resolve-Path $GeyserJar).Path

Write-Host "==> compiling against $(Split-Path $GeyserJar -Leaf)" -ForegroundColor Cyan

if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Path $build -Force | Out-Null
New-Item -ItemType Directory -Path $dist -Force | Out-Null

$sources = Get-ChildItem $src -Recurse -Filter *.java | ForEach-Object { $_.FullName }
if (-not $sources) { throw "no .java sources under $src" }

# javac writes ordinary notes to stderr, and with $ErrorActionPreference = Stop a
# native tool's stderr terminates the script even when it succeeded. Judge it by
# the exit code instead.
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& javac -encoding UTF-8 -proc:none -classpath $GeyserJar -d $build $sources 2>&1 |
    ForEach-Object { Write-Host "    $_" }
$compiled = $LASTEXITCODE
$ErrorActionPreference = $previous
if ($compiled -ne 0) { throw "javac failed with exit code $compiled" }

Copy-Item (Join-Path $res "extension.yml") $build -Force

Write-Host "==> packaging" -ForegroundColor Cyan
if (Test-Path $out) { Remove-Item $out -Force }
& jar --create --file $out -C $build .
if ($LASTEXITCODE -ne 0) { throw "jar failed with exit code $LASTEXITCODE" }

# A jar missing either piece loads as nothing at all, with one quiet line in the
# Geyser log to say so. Cheaper to catch here than in a server console.
$entries = & jar --list --file $out
if ($entries -notcontains "extension.yml") { throw "built jar has no extension.yml" }
if (-not ($entries | Where-Object { $_ -like "*EndlinkGuardExtension.class" })) {
    throw "built jar has no extension class"
}
Write-Host "    $(Split-Path $out -Leaf) ($([math]::Round((Get-Item $out).Length / 1KB, 1)) KB)"

if ($NoDeploy -or -not $DeployTo) {
    if (-not $DeployTo) { Write-Host "==> no -DeployTo given; left in dist\" -ForegroundColor Yellow }
    else { Write-Host "==> skipped deploy (-NoDeploy)" -ForegroundColor Yellow }
    return
}

New-Item -ItemType Directory -Path $DeployTo -Force | Out-Null
Copy-Item $out $DeployTo -Force
Write-Host "==> deployed to $DeployTo" -ForegroundColor Green
Write-Host "    restart Geyser to load it"
