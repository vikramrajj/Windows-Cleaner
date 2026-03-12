@echo off
setlocal
set ROOT=%~dp0
python "%ROOT%cleaner.py" gui
endlocal
