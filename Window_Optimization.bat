@echo off :: Advanced Windows Optimization Batch File :: Make sure to run this as Administrator cls

:: --- Admin Rights Check --- net session >nul 2>&1 if %errorlevel% NEQ 0 ( echo [ERROR] Please run this script as Administrator! pause exit /b )

title [Advanced Windows Optimization & Hang Fix By Yesh ] color 0A

echo ================================================ echo          Advanced Windows Optimization By Yeswant Mishra echo ================================================ echo. timeout /t 2 /nobreak >nul

:: --- Section 1: Disable Unnecessary Services --- echo [1/8] Disabling unnecessary services... :: SysMain (Superfetch) sc stop SysMain >nul 2>&1 sc config SysMain start= disabled >nul 2>&1

:: Windows Search sc stop WSearch >nul 2>&1 sc config WSearch start= disabled >nul 2>&1

:: Windows Update sc stop wuauserv >nul 2>&1 sc config wuauserv start= disabled >nul 2>&1

:: Diagnostic Tracking Service sc stop DiagTrack >nul 2>&1 sc config DiagTrack start= disabled >nul 2>&1

:: Background Intelligent Transfer Service sc stop BITS >nul 2>&1 sc config BITS start= disabled >nul 2>&1

:: Windows Error Reporting sc stop WerSvc >nul 2>&1 sc config WerSvc start= disabled >nul 2>&1

:: Remote Registry sc stop RemoteRegistry >nul 2>&1 sc config RemoteRegistry start= disabled >nul 2>&1

:: Print Spooler sc stop Spooler >nul 2>&1 sc config Spooler start= disabled >nul 2>&1

:: Bluetooth Support Service sc stop bthserv >nul 2>&1 sc config bthserv start= disabled >nul 2>&1

:: Windows Defender Disable (Using Registry) reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul 2>&1

:: Security Center sc stop wscsvc >nul 2>&1 sc config wscsvc start= disabled >nul 2>&1

:: Windows Firewall (Use with caution) sc stop mpssvc >nul 2>&1 sc config mpssvc start= disabled >nul 2>&1

echo Services disabled. timeout /t 1 /nobreak >nul

:: --- Section 2: Clean Junk Files & Temp Directories --- echo [2/8] Cleaning temporary files... del /s /q /f "%temp%*." >nul 2>&1 del /s /q /f "C:\Windows\Temp*." >nul 2>&1 del /s /q /f "C:\Windows\Prefetch*.*" >nul 2>&1 timeout /t 1 /nobreak >nul

:: --- Section 3: Flush DNS & Reset Network Settings --- echo [3/8] Flushing DNS cache and resetting network settings... ipconfig /flushdns >nul netsh int ip reset >nul netsh winsock reset >nul netsh advfirewall reset >nul timeout /t 1 /nobreak >nul

:: --- Section 4: Set High Performance Power Plan --- echo [4/8] Setting High Performance Power Plan... powercfg -setactive SCHEME_MIN >nul timeout /t 1 /nobreak >nul

:: --- Section 5: Disk Cleanup --- echo [5/8] Running Disk Cleanup (Silent Mode)... cleanmgr /sagerun:1 >nul 2>&1 timeout /t 1 /nobreak >nul

:: --- Section 6: Memory Optimization (Standby List) --- echo [6/8] Optimizing RAM (Clearing Standby Memory)... if exist "%~dp0EmptyStandbyList.exe" ( "%~dp0EmptyStandbyList.exe" workingsets >nul 2>&1 "%~dp0EmptyStandbyList.exe" modifiedpagelist >nul 2>&1 "%~dp0EmptyStandbyList.exe" standbylist >nul 2>&1 ) else ( echo [INFO] EmptyStandbyList.exe not found. Skipping memory optimization. ) timeout /t 1 /nobreak >nul

:: --- Section 7: Advanced Registry Tweaks --- echo [7/8] Applying advanced registry tweaks... reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f >nul 2>&1 fsutil behavior set disablelastaccess 1 >nul 2>&1 fsutil behavior set memoryusage 2 >nul 2>&1

:: Disable Hibernation powercfg -h off >nul 2>&1

timeout /t 1 /nobreak >nul

:: --- Section 8: Disable Startup Programs (Optional - Uncomment if needed) --- :: echo [8/8] Disabling startup programs... :: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v [ProgramName] /t REG_SZ /d "" /f

echo. echo ================================================ echo Optimization complete! echo Please RESTART your PC for all changes to take effect. echo ================================================ pause

