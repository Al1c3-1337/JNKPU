@echo off
REM ===========================================================================
REM  Client-Setup OHNE Domaene. Elevated ausfuehren.
REM  Aufruf: setup.cmd BitLocker-NetworkUnlock.cer
REM ===========================================================================
setlocal
if "%~1"=="" ( echo Usage: setup.cmd ^<BitLocker-NetworkUnlock.cer^> & exit /b 1 )
if not exist "%~1" ( echo Datei nicht gefunden: %~1 & exit /b 1 )

echo.
echo === VORHER: Recovery-Key offline greifbar? ===
echo     Ab hier wird an HKLM\SOFTWARE\Policies\Microsoft\FVE geschraubt.
echo     Abbruch mit Ctrl-C, weiter mit Enter.
pause >nul

echo.
echo === Zertifikat in den Policy-Store FVE_NKP ===
REM Das ist der Trick: -grouppolicy schreibt in den Store, den bootmgr liest -
REM ohne Domaene, ohne GPMC. Der Store ist ein serialisierter CryptoAPI-Store,
REM kein rohes DER - deshalb muss certutil das bauen.
certutil -f -grouppolicy -addstore FVE_NKP "%~1"
if errorlevel 1 ( echo FEHLER beim addstore & exit /b 1 )

echo.
echo === Policy-Werte ===
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v OSManageNKP        /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseAdvancedStartup /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UsePIN             /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMPIN          /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPM             /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKey          /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v UseTPMKeyPIN       /t REG_DWORD /d 2 /f
REM 0=disallow 1=require 2=allow. UsePIN=1 falls du TPM+PIN erzwingen willst.

echo.
echo === Kontrolle ===
reg query "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates" 2>nul
if errorlevel 1 ( echo   WARNUNG: FVE_NKP\Certificates ist leer - addstore hat nicht gegriffen. )

echo.
echo === JETZT NEU STARTEN ===
echo     Der Protector erscheint erst nach einem Reboot mit aktiver Policy
echo     und gueltigem Zertifikat im Store.
echo.
echo     Danach pruefen:  manage-bde.exe -protectors -get C:
echo     Gesucht:         "Network (Certificate Based)"   bzw. TpmCertificate (9)
endlocal
