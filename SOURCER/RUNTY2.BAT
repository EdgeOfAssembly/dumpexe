@echo off
echo Starting Sourcer batch
echo G| sr TESTYN2.DEF -n > WORK\TY2.LOG
echo after1 %ERRORLEVEL% >> WORK\TY2.LOG
if exist WORK\TESTYN.LST echo GOT_LST >> WORK\TY2.LOG
if exist TESTYN.LST echo GOT_ROOT_LST >> WORK\TY2.LOG
dir WORK\*.LST >> WORK\TY2.LOG
dir *.LST >> WORK\TY2.LOG
