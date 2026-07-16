echo off
cls
if %2x == x goto nodest
if %2 == a: goto skip1
if %2 == b: goto skip1
if %2 == c: goto skip1
if %2 == d: goto skip1
if %2 == e: goto skip1
if %2 == f: goto skip1
if %2 == g: goto skip1
if %2 == A: goto skip1
if %2 == B: goto skip1
if %2 == C: goto skip1
if %2 == D: goto skip1
if %2 == E: goto skip1
if %2 == F: goto skip1
if %2 == G: goto skip1
if %1x == x goto nodest
if %1 == a: goto skip1
if %1 == b: goto skip1
if %1 == c: goto skip1
if %1 == d: goto skip1
if %1 == e: goto skip1
if %1 == f: goto skip1
if %1 == g: goto skip1
if %1 == A: goto skip1
if %1 == B: goto skip1
if %1 == C: goto skip1
if %1 == D: goto skip1
if %1 == E: goto skip1
if %1 == F: goto skip1
if %1 == G: goto skip1
goto nodest
:skip1
echo ษอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออป
echo บ                                                                             บ
echo บ                            Knights of Legend                                บ
echo บ                                                                             บ
echo บ                       Hard Disk Installation Program                        บ
echo บ                                                                             บ
echo บ     Knights of Legend will be placed in %2\KNIGHTS.  Press any key to       บ
echo บ                                                                             บ
echo บ     begin or Control - C  followed by Y to abort.                           บ
echo บ                                                                             บ
echo ศอออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออออผ
pause
cls
echo Copying files...
md %2\KNIGHTS
%2
cd \KNIGHTS
copy %1\*.*>NUL
insub %2 %1
goto alldone
:nodest
cls
echo Usage : Install [source drive number] [destination drive number]
echo *
echo For example, to Install on drive C from drive A. Type 'Install  A: C:'
:alldone
