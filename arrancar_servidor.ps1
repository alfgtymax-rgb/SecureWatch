# Compatible con Windows PowerShell 5.1
Set-Location -LiteralPath $PSScriptRoot
$PY = Join-Path $env:LOCALAPPDATA "spyder-6\envs\spyder-runtime\python.exe"
if (-not (Test-Path -LiteralPath $PY)) {
    Write-Host "[ERROR] No se encuentra el Python de Spyder en: $PY" -ForegroundColor Red
    Read-Host "Pulsa Enter para salir"
    exit 1
}
Write-Host "=== Instalando dependencias en el entorno de Spyder ===" -ForegroundColor Cyan
& $PY -m pip install fastapi uvicorn requests
if ($LASTEXITCODE -ne 0) { & $PY -m pip install --user fastapi uvicorn requests }
Write-Host ""
Write-Host "=== Arrancando servidor SecureWatch en http://localhost:8000 (Ctrl+C para detener) ===" -ForegroundColor Green
& $PY -m uvicorn server:app --host 0.0.0.0 --port 8000
Read-Host "Pulsa Enter para cerrar"
