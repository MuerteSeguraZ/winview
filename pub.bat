@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=more cert info and fix garbage data in EV_EFI_HCRTM_EVENT"

git status

git commit -m "%MSG%"

git push origin main

pause
