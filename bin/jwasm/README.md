# Historical JWASM toolchains (versioned)

Kept for **ground-truth rebuilds** of era DOS software (e.g. CuteMouse 2.1b4).

| File | Version | Date | Notes |
|------|---------|------|--------|
| `jwasm-1.8.exe` | **1.80** Win32 | 2008-06-21 | Preferred for CuteMouse |
| `jwasmd-1.8.exe` | **1.80** DOS/DPMI | 2008-06-21 | `jwasmd` name used in CuteMouse makefile |
| `jwasm-1.7.exe` | **1.7** Win32 | 2008-05-20 | First public JWASM |
| `jwasmd-1.7.exe` | **1.7** DOS/DPMI | 2008-05-20 | |

## CuteMouse proof

With **jwasm-1.8** + CuteMouse sources + wlink/exe2bin + com2exe-style wrap, the load image (and full EXE with matching header) is **byte-identical** to shipped `games/cutemouse/bin/ctmouse.exe`.

```bash
# Example (Linux host):
wine bin/jwasm/jwasm-1.8.exe -mt -Iasmlib -Iasmlib\\bios ... -Fo ctmouse.obj ctmouse.asm
```

## Archives

`archives/` holds original SourceForge zips (`JWasm180s.zip`, `JWasm180b.zip`, `JWasm170s.zip`, `JWasm170b.zip`).

## License

Sybase Open Watcom Public License — see `LICENSE.TXT`.

## Naming

Always **suffix with version** (`jwasm-1.8`, not bare `jwasm`) so multiple eras can coexist.
