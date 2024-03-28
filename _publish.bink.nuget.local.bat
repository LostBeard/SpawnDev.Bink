@echo off
@REM This script finds the latest nupkg file for the given project, asks for the apikey (secret), then publishes
@REM All paths used are relative the project folder
set projectPath=%~dp0SpawnDev.Bink
set releaseFolder=%projectPath%\bin\Release
@REM Finding latest nupkg

@echo:

FOR /F "eol=| delims=" %%I IN ('DIR "%releaseFolder%\*.nupkg" /A-D /B /O-D /TW 2^>nul') DO SET "NewestFile=%%I" & GOTO FoundFile
ECHO No *.nupkg file found
GOTO :EOF

:FoundFile
ECHO Latest *.nupkg file is:
ECHO %NewestFile%

setlocal
:PROMPT
SET /P AREYOUSURE=Publish this package? y/[N]? 

IF /I "%AREYOUSURE%" NEQ "Y" GOTO END

set /p apikey=Enter api key: 
@IF NOT [%apikey%] == [] (
    REM dotnet nuget push "%releaseFolder%\%NewestFile%" --api-key %apikey% --source https://api.nuget.org/v3/index.json
    nuget add "%releaseFolder%\%NewestFile%" -source "D:\users\SpawnDevPackages"
) else (
    @echo Cancelled
)
:END
endlocal

pause
