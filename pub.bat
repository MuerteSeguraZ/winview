@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=fix EV_EFI_PLATFORM_FIRMWARE_BLOB2 because windows is so aids it names it that even tho its a gpt header"

git status

git commit -m "%MSG%"

git push origin main

pause
