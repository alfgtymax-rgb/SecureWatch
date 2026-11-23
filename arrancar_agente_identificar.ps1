# Compatible con Windows PowerShell 5.1
# SecureWatch Semana 10: agente con identificación de vulnerabilidades (NVD).
Set-Location -LiteralPath $PSScriptRoot
$PY = Join-Path $env:LOCALAPPDATA "spyder-6\envs\spyder-runtime\python.exe"
if (-not (Test-Path -LiteralPath $PY)) {
    Write-Host "[ERROR] No se encuentra el Python de Spyder en: $PY" -ForegroundColor Red
    Read-Host "Pulsa Enter para salir"
    exit 1
}
& $PY -m pip install --quiet packaging requests
if ([string]::IsNullOrWhiteSpace($env:NVD_API_KEY)) {
    Write-Host "Aviso: NVD_API_KEY no definida. La consulta a la NVD sera lenta (6 s por peticion)." -ForegroundColor Yellow
} else {
    Write-Host "NVD_API_KEY detectada: consultas rapidas." -ForegroundColor Cyan
}
Write-Host "=== Arrancando agente SecureWatch con --identificar (Ctrl+C para detener) ===" -ForegroundColor Green
& $PY main.py --identificar
Read-Host "Pulsa Enter para cerrar"
