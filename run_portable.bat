@echo off
setlocal
REM Ir al directorio del script .bat
cd /d "%~dp0"
REM Intentar con python, si no existe, probar con py -3
where python >nul 2>&1
if %ERRORLEVEL%==0 (
 set RUNNER=python
) else (
 where py >nul 2>&1
 if %ERRORLEVEL%==0 (
   set RUNNER=py -3
 ) else (
   echo ERROR: No se encontro Python en PATH.
   echo Instala Python 3.8+ o ejecuta manualmente desde CMD.
   pause
   exit /b 1
 )
)
REM Lanza el wizard SIN argumentos (asi aparece el menu)
%RUNNER% convert.py
echo.
echo (Si hubo errores, revisa migration.log y report.json en la carpeta 'output' que elijas)
pause
