@echo off
REM Automated build script for NSFW DLL on Windows 11
REM Prerequisites: Visual Studio 2022+ with C++ workload installed

REM Set up environment (adjust path if needed)
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

REM Build the solution in Release mode
msbuild core\nightmare\nightmare.sln /p:Configuration=Release /p:Platform=x64

REM Output location
if exist core\nightmare\x64\Release\nightmare.dll (
    echo Build succeeded! DLL is at core\nightmare\x64\Release\nightmare.dll
) else (
    echo Build failed. Check the output above for errors.
)

pause
