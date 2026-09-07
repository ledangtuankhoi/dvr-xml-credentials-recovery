@echo off
setlocal enabledelayedexpansion
title CCTV Device Config Decryptor & Parser Utility

if "%~1"=="" (
    echo.
    echo =======================================================
    echo   CCTV Configuration XML Decryptor Utility
    echo =======================================================
    echo.
    echo Usage:   cctv_xml_decoder.cmd ^<path_to_device_config.xml^>
    echo Example: cctv_xml_decoder.cmd devices.xml
    echo.
    set /p "xmlpath=Enter XML File Path: "
    if "!xmlpath!"=="" exit /b 0
    set "TARGET=!xmlpath!"
) else (
    set "TARGET=%~1"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cctv_xml_decoder.ps1" -Path "!TARGET!"
echo.
pause
