# Build the local Myntra Partner Packing EXE beside this source file.
# The EXE is self-contained; the JSON settings file is created only after
# first-run Settings are saved and is never required to distribute the EXE.
$ErrorActionPreference = "Stop"
$Folder = (Resolve-Path $PSScriptRoot).Path
$Source = Join-Path $Folder "myntra_manual.py"
$Output = Join-Path $Folder "MyntraPartnerManual.exe"
$Dist = Join-Path $Folder ".build-dist"
$Work = Join-Path $Folder ".build-work"
$Spec = Join-Path $Folder ".build-spec"
$EmbeddedEnv = Join-Path $Folder ".embedded.env"
$RootEnv = Join-Path (Split-Path $Folder -Parent) ".env"
$Config = Join-Path $Folder "myntra_manual_config.json"

try {
  $dbLine = $null
  if (Test-Path -LiteralPath $RootEnv) {
    $dbLine = Get-Content -LiteralPath $RootEnv | Where-Object { $_ -match '^\s*CONSIGMENT_APP_DATABASE_URL\s*=' } | Select-Object -First 1
  }
  if (-not $dbLine -and (Test-Path -LiteralPath $Config)) {
    $settings = Get-Content -Raw -LiteralPath $Config | ConvertFrom-Json
    $dbValue = [string]$settings.consignment_database_url
    if (-not $dbValue -and $settings.consignment_database_url_encrypted) {
      $protected = [Convert]::FromBase64String([string]$settings.consignment_database_url_encrypted)
      $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
      )
      $dbValue = [Text.Encoding]::UTF8.GetString($plain)
    }
    if ($dbValue) { $dbLine = "CONSIGMENT_APP_DATABASE_URL=$dbValue" }
  }
  if (-not $dbLine) {
    throw "CONSIGMENT_APP_DATABASE_URL is missing from both $RootEnv and the protected local app settings."
  }
  Set-Content -LiteralPath $EmbeddedEnv -Value $dbLine -Encoding UTF8

  python -m py_compile $Source
  if ($LASTEXITCODE -ne 0) { throw "Python compilation failed." }
  pyinstaller --noconfirm --onefile --windowed --name MyntraPartnerManual `
    --distpath $Dist --workpath $Work --specpath $Spec `
    --add-data "$EmbeddedEnv;." `
    --exclude-module PyQt5 --exclude-module PySide6 --exclude-module IPython --exclude-module matplotlib `
    --hidden-import tkinter --hidden-import playwright.sync_api --hidden-import psycopg $Source
  if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
  Copy-Item -LiteralPath (Join-Path $Dist "MyntraPartnerManual.exe") -Destination $Output -Force
  Write-Host "Built: $Output" -ForegroundColor Green
} finally {
  if (Test-Path -LiteralPath $EmbeddedEnv) { [System.IO.File]::Delete($EmbeddedEnv) }
}
