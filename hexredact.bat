@echo off
rem hexredact launcher for Windows.
rem   Double-click: opens the interactive wizard.
rem   Drag a log file or folder onto this file: opens the wizard with that path.
rem Works from a clone without installing (uses .\src); an installed hexredact works too.
setlocal
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "PY=python"
where python >nul 2>nul || set "PY=py"
%PY% -m hexredact wizard --pause %1
endlocal
