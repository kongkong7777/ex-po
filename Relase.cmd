cls
@echo off

for %%a in (
bjexcas002
bjexcas003
bjexcas004
) do (
copy /y "%~dp0PW.Auth.Monitoring.ps1" "\\%%a\C$\Scripts\Against Password Hacking\"
copy /y "%~dp0FW_WhiteList.txt" "\\%%a\C$\Scripts\Against Password Hacking\"
copy /y "%~dp0FW_BlackList.txt" "\\%%a\C$\Scripts\Against Password Hacking\"
)

pause
