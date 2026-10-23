@echo off
setlocal EnableExtensions EnableDelayedExpansion
title ADB Repair + Start Server - All-in-One
color 0B

:: ============================================================
:: ADB + Xiaomi Mi Assistant Mode helper for Windows 10/11
:: Downloads Google's official Android Platform Tools.
:: Installs only valid driver packages supplied in .\Drivers.
:: Run as Administrator for PATH and driver installation.
:: ============================================================

set "TOOL_NAME=ADB + Xiaomi Assistant Mode Repair"
set "INSTALL_DIR=%SystemDrive%\Android\platform-tools"
set "DRIVER_DIR=%~dp0Drivers"
set "LOG_DIR=%ProgramData%\ADB_Xiaomi_Repair"
set "LOG_FILE=%LOG_DIR%\setup.log"
set "ZIP_FILE=%TEMP%\platform-tools-latest-windows.zip"
set "DOWNLOAD_URL=https://dl.google.com/android/repository/platform-tools-latest-windows.zip"

if not exist "%LOG_DIR%" md "%LOG_DIR%" >nul 2>&1
call :log ============================================================
call :log Started %DATE% %TIME%
call :log Script: %~f0

:MENU
cls
echo ============================================================
echo   ADB REPAIR + START SERVER - ALL-IN-ONE
echo ============================================================
echo   1. Repair ADB + Install Drivers + Start ADB Server
echo   2. Install / update Google ADB Platform Tools
echo   3. Show USB / ADB driver diagnostics
echo   4. Open Windows Device Manager
echo   5. Exit
echo.
echo   Log: %LOG_FILE%
echo ============================================================
choice /c 12345 /n /m "Choose an option [1-5]: "
if errorlevel 5 goto :END
if errorlevel 4 goto :DEVICE_MANAGER
if errorlevel 3 goto :DIAGNOSTICS
if errorlevel 2 goto :INSTALL_ADB
if errorlevel 1 goto :FULL_SETUP
goto :MENU

:FULL_SETUP
call :require_admin
if errorlevel 1 goto :MENU
call :install_adb
call :set_path
call :install_drivers
call :adb_repair
call :diagnostics
echo.
echo All-in-one repair finished. ADB server has been started and device status checked.
echo Review any warnings above and the log file.
pause
goto :MENU

:INSTALL_ADB
call :require_admin
if errorlevel 1 goto :MENU
call :install_adb
call :set_path
echo.
pause
goto :MENU

:INSTALL_DRIVERS
call :require_admin
if errorlevel 1 goto :MENU
call :install_drivers
echo.
pause
goto :MENU

:ADB_REPAIR
call :adb_repair
echo.
pause
goto :MENU

:DIAGNOSTICS
call :diagnostics
echo.
pause
goto :MENU

:DEVICE_MANAGER
start "" devmgmt.msc
goto :MENU

:require_admin
net session >nul 2>&1
if not errorlevel 1 exit /b 0
echo.
echo [ADMIN REQUIRED] Close this window, then right-click the BAT file
echo and choose "Run as administrator".
call :log ERROR: Administrator privileges required.
pause
exit /b 1

:install_adb
echo.
echo [1/3] Checking Android Platform Tools...
if exist "%INSTALL_DIR%\adb.exe" (
    echo Existing ADB found: %INSTALL_DIR%
    "%INSTALL_DIR%\adb.exe" version
    choice /c YN /n /m "Download and update official Google Platform Tools? [Y/N]: "
    if errorlevel 2 (
        call :log Kept existing Platform Tools.
        exit /b 0
    )
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: PowerShell not found. Cannot download Platform Tools automatically.
    call :log ERROR: PowerShell not found.
    exit /b 1
)
echo Downloading official Google Platform Tools...
echo Source: %DOWNLOAD_URL%
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ErrorActionPreference='Stop'; try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%ZIP_FILE%' -UseBasicParsing; if ((Get-Item '%ZIP_FILE%').Length -lt 1000000) { throw 'Downloaded archive is unexpectedly small.' }; Write-Host 'Download complete.' } catch { Write-Error $_; exit 1 }"
if errorlevel 1 (
    echo ERROR: Download failed. Check internet, proxy, or antivirus settings.
    call :log ERROR: Platform Tools download failed.
    exit /b 1
)
if not exist "%INSTALL_DIR%" md "%INSTALL_DIR%" >nul 2>&1
echo Extracting tools...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ErrorActionPreference='Stop'; try { Expand-Archive -LiteralPath '%ZIP_FILE%' -DestinationPath '%TEMP%\adb_xiaomi_extract' -Force; $src='%TEMP%\adb_xiaomi_extract\platform-tools'; if (!(Test-Path (Join-Path $src 'adb.exe'))) { throw 'adb.exe missing from archive.' }; if (!(Test-Path '%SystemDrive%\Android')) { New-Item -ItemType Directory -Path '%SystemDrive%\Android' -Force | Out-Null }; if (Test-Path '%INSTALL_DIR%') { Remove-Item '%INSTALL_DIR%' -Recurse -Force }; Copy-Item $src '%SystemDrive%\Android\' -Recurse -Force; Write-Host 'Installed to %INSTALL_DIR%' } catch { Write-Error $_; exit 1 }"
if errorlevel 1 (
    echo ERROR: Extraction or installation failed.
    call :log ERROR: Platform Tools extraction/install failed.
    exit /b 1
)
del "%ZIP_FILE%" >nul 2>&1
call :log Installed/updated Google Platform Tools at %INSTALL_DIR%.
echo ADB version:
"%INSTALL_DIR%\adb.exe" version
exit /b 0

:set_path
echo.
echo [2/3] Adding ADB folder to system PATH...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
 "$ErrorActionPreference='Stop'; $p=[Environment]::GetEnvironmentVariable('Path','Machine'); $d='%INSTALL_DIR%'; if (($p -split ';') -notcontains $d) { [Environment]::SetEnvironmentVariable('Path', (($p.TrimEnd(';') + ';' + $d).Trim(';')), 'Machine'); Write-Host 'System PATH updated.' } else { Write-Host 'ADB folder already exists in system PATH.' }"
if errorlevel 1 (
    echo WARNING: Could not update system PATH. ADB still works from %INSTALL_DIR%.
    call :log WARNING: System PATH update failed.
) else (
    call :log System PATH checked/updated.
)
set "PATH=%INSTALL_DIR%;%PATH%"
exit /b 0

:install_drivers
echo.
echo [3/3] Installing available driver packages...
echo.
echo This step installs only INF driver packages that you place in:
echo "%DRIVER_DIR%"
echo.
echo Put trusted, correctly signed Xiaomi / Qualcomm / ADB USB driver
echo INF packages in that folder first. Do not use unknown driver packs.
if not exist "%DRIVER_DIR%" (
    md "%DRIVER_DIR%" >nul 2>&1
    echo Created Drivers folder:
    echo "%DRIVER_DIR%"
    echo No driver package was supplied, so no third-party driver was installed.
    echo Get the correct driver package from your device/OEM source, extract it,
    echo then rerun option 1.
    call :log No Drivers folder existed; created it. No driver installed.
    exit /b 0
)
set "FOUND_INF="
for /r "%DRIVER_DIR%" %%F in (*.inf) do (
    set "FOUND_INF=1"
    echo Installing: %%~fF
    pnputil.exe /add-driver "%%~fF" /install
    if errorlevel 1 (
        echo WARNING: Driver package returned an error: %%~nxF
        call :log WARNING: pnputil returned error for %%~fF
    ) else (
        call :log Driver package processed: %%~fF
    )
)
if not defined FOUND_INF (
    echo No .INF files found in "%DRIVER_DIR%".
    echo Extract your trusted driver package into this folder, preserving subfolders.
    call :log No INF files found in Drivers folder.
) else (
    echo Driver scan complete. A reboot or reconnect may be needed.
)
exit /b 0

:adb_repair
echo.
echo [ADB] Restarting ADB server...
set "ADB_EXE=%INSTALL_DIR%\adb.exe"
if not exist "%ADB_EXE%" (
    where adb.exe >nul 2>&1
    if not errorlevel 1 set "ADB_EXE=adb.exe"
)
if not exist "%ADB_EXE%" if /i not "%ADB_EXE%"=="adb.exe" (
    echo ADB not found. Run option 2 first, then use option 1.
    call :log ADB executable not found.
    exit /b 1
)
"%ADB_EXE%" kill-server
"%ADB_EXE%" start-server
echo.
echo Connected ADB devices:
"%ADB_EXE%" devices -l
echo.
echo If device shows "unauthorized", unlock the phone and accept the RSA prompt.
echo For recovery / Mi Assistant mode, it may not appear in "adb devices";
echo that mode may require the exact Xiaomi/Qualcomm USB driver for the device.
call :log ADB server restarted and device list queried.
exit /b 0

:diagnostics
echo.
echo ================= USB / ADB DIAGNOSTICS =================
echo Windows:
ver
echo.
echo ADB executable:
if exist "%INSTALL_DIR%\adb.exe" (
    "%INSTALL_DIR%\adb.exe" version
) else (
    where adb.exe 2>nul
)
echo.
echo ADB devices:
if exist "%INSTALL_DIR%\adb.exe" "%INSTALL_DIR%\adb.exe" devices -l
echo.
echo Connected USB devices (PnPUtil):
pnputil.exe /enum-devices /connected /class USB 2>nul
echo.
echo Connected Android / ADB-class devices (if supported by this Windows build):
pnputil.exe /enum-devices /connected /class AndroidUsbDeviceClass 2>nul
echo.
echo Driver packages containing likely keywords:
pnputil.exe /enum-drivers | findstr /i "android adb xiaomi qualcomm google winusb"
echo.
echo Troubleshooting:
echo - Use a known data-capable USB cable and a direct USB port.
echo - Unlock phone; enable USB debugging for normal ADB mode.
echo - Select File Transfer (MTP) if normal Android mode is not detected.
echo - In Recovery / Mi Assistant mode, normal ADB may not be available.
echo - Driver installation depends on a matching INF for your exact device/mode.
echo - Avoid disabling Windows driver-signature enforcement.
call :log Diagnostics completed.
exit /b 0

:log
>>"%LOG_FILE%" echo [%DATE% %TIME%] %*
exit /b 0

:END
echo.
echo Exiting. Log saved at:
echo %LOG_FILE%
endlocal
exit /b 0
