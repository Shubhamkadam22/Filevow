<#
.SYNOPSIS
  Build the FileVow desktop app and its Windows installer.

.DESCRIPTION
  1. Builds the dashboard (web/frontend -> dist)
  2. Creates a clean build environment and installs the backend with PyInstaller
  3. Bundles FileVow.exe with PyInstaller (web/packaging/windows/build/dist/FileVow)
  4. Builds FileVow-Setup-<version>.exe with Inno Setup 6 when it is installed
  5. Writes SHA-256 checksums and a versionless FileVow-Setup.exe for "latest" download links

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File web\packaging\windows\build.ps1
#>
[CmdletBinding()]
param(
  [switch]$SkipDashboard,
  [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$here     = $PSScriptRoot
$web      = Resolve-Path (Join-Path $here "..\..")
$frontend = Join-Path $web "frontend"
$backend  = Join-Path $web "backend"
$build    = Join-Path $here "build"
$dist     = Join-Path $here "dist"
$version  = (Select-String -Path (Join-Path $backend "pyproject.toml") -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

New-Item -ItemType Directory -Force $build, $dist | Out-Null

if (-not $SkipDashboard) {
  Step "Building the dashboard"
  Push-Location $frontend
  try {
    npm ci
    if ($LASTEXITCODE) { throw "npm ci failed" }
    npm run build
    if ($LASTEXITCODE) { throw "dashboard build failed" }
  } finally { Pop-Location }
}

Step "Preparing the build environment"
$venv = Join-Path $build "venv"
if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) { python -m venv $venv }
$python = Join-Path $venv "Scripts\python.exe"
& $python -m pip install --upgrade --quiet pip
& $python -m pip install --quiet "$backend[desktop]" "pyinstaller>=6.10" "pillow>=10"
if ($LASTEXITCODE) { throw "pip install failed" }

Step "Drawing the app icon"
& $python (Join-Path $here "make_icon.py") (Join-Path $build "filevow.ico")

Step "Bundling FileVow.exe"
$env:FILEVOW_DASHBOARD_DIST = Join-Path $frontend "dist"
& $python -m PyInstaller (Join-Path $here "FileVow.spec") --noconfirm --clean `
  --distpath (Join-Path $build "dist") --workpath (Join-Path $build "work")
if ($LASTEXITCODE) { throw "PyInstaller failed" }

$exe = Join-Path $build "dist\FileVow\FileVow.exe"
Step "Smoke test: FileVow.exe --help"
$help = & $exe --help 2>&1 | Out-String
# A windowed exe prints nothing to this console; a non-zero exit code means it crashed.
if ($LASTEXITCODE) { throw "FileVow.exe exited with code $LASTEXITCODE`n$help" }

if ($SkipInstaller) { Write-Host "`nApp folder ready: $(Split-Path $exe)"; return }

$iscc = @(
  (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source,
  "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
  "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
  "$env:LocalAppData\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $iscc) {
  Write-Warning "Inno Setup 6 was not found, so no installer was built. Install it with:  winget install JRSoftware.InnoSetup"
  Write-Host "App folder ready: $(Split-Path $exe)"
  return
}

Step "Building the installer"
& $iscc "/DAppVersion=$version" (Join-Path $here "installer.iss")
if ($LASTEXITCODE) { throw "Inno Setup failed" }

$setup = Join-Path $dist "FileVow-Setup-$version.exe"
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
"$hash  FileVow-Setup-$version.exe" | Set-Content -Encoding ascii "$setup.sha256"

# A copy without the version gives the website a permanent "latest" link:
# https://github.com/<owner>/<repo>/releases/latest/download/FileVow-Setup.exe
$latest = Join-Path $dist "FileVow-Setup.exe"
Copy-Item $setup $latest -Force
"$hash  FileVow-Setup.exe" | Set-Content -Encoding ascii "$latest.sha256"

Step "Done"
Write-Host "Installer: $setup"
Write-Host "SHA-256:   $hash"
Write-Host "Attach everything in $dist to a GitHub Release (the release workflow does this for you)."
