@echo off
echo === Protector vorhanden? ===
manage-bde.exe -protectors -get C: | findstr /i "Network Certificate TpmCertificate"
echo.
echo === OSManageNKP ===
reg query "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v OSManageNKP
echo.
echo === Zertifikat im FVE_NKP-Store ===
reg query "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\FVE_NKP\Certificates"
echo.
echo Der Eintragsname muss dem Thumbprint des Zertifikats entsprechen.
