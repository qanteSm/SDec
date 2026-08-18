@echo off
chcp 65001 >nul
title SDec

set "SDEC_DIR=%~dp0"
set "ANALYZER=%SDEC_DIR%analyzer\engine.py"

if "%1"=="--help" (
    echo.
    echo   SDec
    echo   ====
    echo.
    echo   sdec_run.bat              
    echo   sdec_run.bat --md         
    echo   sdec_run.bat --quick      
    echo   sdec_run.bat --deep       
    echo   sdec_run.bat --network    
    echo   sdec_run.bat --save-baseline
    echo   sdec_run.bat --analyze-only
    echo.
    exit /b 0
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    where python3 >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python not found.
        pause
        exit /b 1
    )
    set "PYTHON=python3"
) else (
    set "PYTHON=python"
)

set "ARGS="

if "%1"=="--quick" (
    echo [MODE] Quick
    %PYTHON% -c "import json;c=json.load(open('%SDEC_DIR%config.json'));c['layers']={k:(k in ['memory','persistence','network']) for k in c['layers']};json.dump(c,open('%SDEC_DIR%config.tmp.json','w'),indent=2)"
    copy /y "%SDEC_DIR%config.tmp.json" "%SDEC_DIR%config.json" >nul
    del "%SDEC_DIR%config.tmp.json" 2>nul
)

if "%1"=="--deep" (
    echo [MODE] Deep
    %PYTHON% -c "import json;c=json.load(open('%SDEC_DIR%config.json'));c['layers']={k:True for k in c['layers']};c['timeout_seconds']=120;json.dump(c,open('%SDEC_DIR%config.tmp.json','w'),indent=2)"
    copy /y "%SDEC_DIR%config.tmp.json" "%SDEC_DIR%config.json" >nul
    del "%SDEC_DIR%config.tmp.json" 2>nul
)

if "%1"=="--network" (
    echo [MODE] Network
    %PYTHON% -c "import json;c=json.load(open('%SDEC_DIR%config.json'));c['layers']={k:(k=='network') for k in c['layers']};json.dump(c,open('%SDEC_DIR%config.tmp.json','w'),indent=2)"
    copy /y "%SDEC_DIR%config.tmp.json" "%SDEC_DIR%config.json" >nul
    del "%SDEC_DIR%config.tmp.json" 2>nul
)

for %%a in (%*) do (
    if "%%a"=="--md" set "ARGS=%ARGS% --md"
    if "%%a"=="--save-baseline" set "ARGS=%ARGS% --save-baseline"
    if "%%a"=="--analyze-only" set "ARGS=%ARGS% --analyze-only"
)

cd /d "%SDEC_DIR%analyzer"
%PYTHON% engine.py %ARGS%

echo.
pause
