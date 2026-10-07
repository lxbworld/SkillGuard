@echo off
REM Developer helper: sets up the MSVC + Rust toolchain for SkillGuard.
REM Usage:  tools\env.cmd  (call it, then run cargo normally)
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

if exist "D:\VSBuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64" (
  set "PATH=D:\VSBuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;%PATH%"
)

REM Windows SDK: link.exe needs the SDK libraries on some operations.
for /d %%D in ("D:\VSBuildTools\Windows Kits\10\Lib\*") do set "SG_SDK=%%~nxD"
if defined SG_SDK if exist "D:\VSBuildTools\Windows Kits\10\bin\%SG_SDK%\x64" (
  set "PATH=D:\VSBuildTools\Windows Kits\10\bin\%SG_SDK%\x64;%PATH%"
  set "INCLUDE=D:\VSBuildTools\VC\Tools\MSVC\14.44.35207\include;%INCLUDE%"
  set "LIB=D:\VSBuildTools\VC\Tools\MSVC\14.44.35207\lib\x64;%PATH%"
)

REM Domestic network is direct; international goes through the local proxy.
if not defined HTTP_PROXY  set "HTTP_PROXY=http://127.0.0.1:7897"
if not defined HTTPS_PROXY set "HTTPS_PROXY=http://127.0.0.1:7897"
