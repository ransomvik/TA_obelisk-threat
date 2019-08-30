@echo off
SET SPLUNKPATH="C:\Program Files\Splunk"

echo [*] Starting python threat list script. 
"%SPLUNKPATH%\bin\splunk.exe" cmd python "%SPLUNKPATH%\etc\apps\TA_obelisk-threat\bin\obelisk_threat_intel.py"
echo [*] Looking for old log files to clear.
forfiles -p "%SPLUNKPATH%\etc\apps\TA_obelisk-threat\logs" -s -m obelisk_*.log -d -2 -c "cmd /c del @path"
