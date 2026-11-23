@echo off
chcp 65001 > nul
title SecureWatch - Agente

echo ============================================
echo   SecureWatch - Semana 9: Agente
echo ============================================
echo.

:: Ir a la carpeta donde esta este .bat
cd /d "%~dp0"

echo Arrancando el agente...
echo El agente enviara un HEARTBEAT cada 30 segundos.
echo Para detenerlo pulsa Ctrl+C.
echo.

python main.py

echo.
echo Agente detenido.
pause
