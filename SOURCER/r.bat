@echo off
sr t.def -n -x
if exist t.lst echo OK_LST
dir t.*
