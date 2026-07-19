@echo off
rem Batch Sourcer on ICON.EXE (-n no direct screen, -x quiet)
sr WORK\ICON.DEF -n -x > WORK\SR.LOG
echo DONE >> WORK\SR.LOG
