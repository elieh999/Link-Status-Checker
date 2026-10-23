$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

py -m pip install -r requirements-dev.txt pyinstaller
py scripts\create_icon.py
py -m ruff check .
py -m ruff format --check .
py -m pytest -m "not network"
py -m PyInstaller --noconfirm --clean LinkStatusChecker.spec

$Exe = Join-Path $ProjectRoot "dist\LinkStatusChecker.exe"
if (-not (Test-Path -LiteralPath $Exe)) {
    throw "LinkStatusChecker.exe was not created."
}

$SmokeOutput = Join-Path $ProjectRoot "dist\smoke_test_result.txt"
& $Exe --smoke-test --smoke-output $SmokeOutput
if ($LASTEXITCODE -ne 0) {
    throw "The packaged smoke test failed with exit code $LASTEXITCODE."
}

$Size = (Get-Item -LiteralPath $Exe).Length
Write-Host "Built: $Exe"
Write-Host "Size: $Size bytes"
Get-Content -LiteralPath $SmokeOutput
