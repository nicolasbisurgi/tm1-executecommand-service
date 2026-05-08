@echo off
REM This script lives in C:\Scripts\Outside\ which is NOT in allowed_directories.
REM Any attempt to invoke it should be rejected by the command policy with HTTP 403.
echo this should never run via the service
