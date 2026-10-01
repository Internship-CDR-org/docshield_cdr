@echo off
REM ==============================================================================
REM DocShield CDR Engine - Windows Command Prompt Sandbox Launcher
REM ==============================================================================

if "%~2"=="" (
    echo DocShield Sandbox: Please provide an input file and an output file.
    echo Usage: sandbox-run.bat ^<input-file^> ^<output-file^>
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sandbox-run.ps1" "%~1" "%~2"
exit /b %ERRORLEVEL%
