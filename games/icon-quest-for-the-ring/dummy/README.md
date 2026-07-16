# ICON dummy stub (v2)

Minimal DOS program that **mimics ICON terrain display**, then you explore and quit.

## Behavior

1. FCB load **`BA.DAT`** + **`BB.DAT`** (optional) + **`LA.MAP`**
2. BIOS **mode 01h** (40×25 color text)
3. Clear **B800** to `00 00`, blit **19×4** stamps (ICON1 grid)
4. Stamp id = **full MAP byte** mod 192 (BA‖BB)
5. **Keys**
   - **←↑↓→** — move camera
   - **R** — reset camera to (7, 75)
   - **ESC** — mode 03h + exit

## Build

```bash
cd games/icon-quest-for-the-ring/dummy
make && make install
```

## Run

From **`ICON/`** (needs `BA.DAT`, `BB.DAT`, `LA.MAP`):

```text
icon_dummy.com
```

DOS 8.3 name → screen dumps show as **`ICON_D1_...`**.

## Compare

Offline expected buffer (cam 7,75): regenerate with Python if needed, or after a
hotkey dump:

```bash
# viewport should match offline algorithm (margin zeros vs BIOS spaces only if clear ran)
xxd -s 0xa0 -l 64 ICON/screen_dumps/ICON_D1_*m01*0002.bin
```
