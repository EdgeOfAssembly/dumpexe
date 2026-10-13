# Third-party notices

## ne_names.h — Win16 ordinal names

The KERNEL, USER and GDI ordinal-to-name tables in `ne_names.h` list the
ordinal numbers and export names of the Windows 3.x system modules. They were
generated from the Wine project's 16-bit spec files (`krnl386.exe16.spec`,
`user.exe16.spec`, `gdi.exe16.spec`, https://gitlab.winehq.org/wine/wine).
Wine is licensed under the GNU LGPL 2.1 or later. Only the ordinal/name pairs
(interface facts of the Windows API) are used; no Wine source code is
included. Wine-internal pseudo-exports (`__wine_*`) were removed.
