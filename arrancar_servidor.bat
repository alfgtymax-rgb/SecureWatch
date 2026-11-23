@echo off
chcp 65001 > nul
title SecureWatch - Servidor

echo ============================================
echo   SecureWatch - Semana 9: Servidor FastAPI
echo ============================================
echo.

:: Ir a la carpeta donde esta este .bat
cd /d "%~dp0"

echo [1/2] Instalando dependencias (si ya estan, se omite)...
pip install fastapi uvicorn requests --quiet
echo.

echo [2/2] Arrancando el servidor en http://0.0.0.0:8000 ...
echo.
echo  Abre el navegador en:  http://127.0.0.1:8000/api/inventario
echo  Documentacion API:     http://127.0.0.1:8000/docs
echo.
echo  Para parar el servidor pulsa Ctrl+C
echo.

python -m uvicorn server:app --host 0.0.0.0 --port 8000

echo.
echo Servidor detenido.
pause
