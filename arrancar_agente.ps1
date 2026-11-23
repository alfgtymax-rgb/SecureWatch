# Compatible con Windows PowerShell 5.1
Set-Location -LiteralPath $PSScriptRoot
$PY = Join-Path $env:LOCALAPPDATA "spyder-6\envs\spyder-runtime\python.exe"
if (-not (Test-Path -LiteralPath $PY)) {
    Write-Host "[ERROR] No se encuentra el Python de Spyder en: $PY" -ForegroundColor Red
    Read-Host "Pulsa Enter para salir"
    exit 1
}
Write-Host "=== Arrancando agente SecureWatch (Ctrl+C para detener) ===" -ForegroundColor Green
& $PY main.py
Read-Host "Pulsa Enter para cerrar"
