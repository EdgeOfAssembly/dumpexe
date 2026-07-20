@echo off
sr WORK\TY.DEF -n -x > WORK\TY.LOG
echo EXIT %ERRORLEVEL% >> WORK\TY.LOG
