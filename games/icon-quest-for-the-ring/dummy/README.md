# ICON dummy loader (v4)

DOS COM that mirrors **ICON.EXE load staging** in assembly, then runs the
proven terrain play loop. Not a full Pascal MT+ reimplementation — same
**order of modes, FCB names, and ESC-skippable intros**, then PLAY.

## Visual order (matches real ICON.EXE)

| # | You see in ICON.EXE | Dummy stage | Asset (8.3) |
|---|---------------------|-------------|-------------|
| 1 | Title — gold ring “icon” (`/tmp/start.png`) | `STAGE_TITLE` | `TITLE.BIN` |
| 2 | After ESC — particle/anim (`/tmp/animation.png`) | `STAGE_ANI` | `ANI.BIN` |
| 3 | (overlay load) | `STAGE_OVL0` | FCB `ICON0.OVL` (read+discard) |
| 4 | Level assets | `STAGE_ASSETS` | `BA.DAT`… or `STAMPS.BIN`+`MAPRT.BIN` |
| 5 | (gameplay overlay) | `STAGE_OVL1` | FCB `ICON1.OVL` (read+discard) |
| 6 | Overworld terrain | `STAGE_PLAY` | map→stamp blit |

Real chain (live log):

```text
ICON.EXE → mode 00/01 title → (ESC) animation → ICON0.OVL
         → BA.DAT, LA.MAP, LA.DAT, MA.DAT → ICON1.OVL → play
```

## Capture authentic TITLE / ANI pages

Auto dumps right after mode-set often hit **mid-paint** (incomplete ring).
For screens that match `start.png` / `animation.png`:

1. Run **ICON.EXE** in DOSBox with `screen_dump = true`.
2. On the **first** screen (title): **Ctrl+F10** → copy that `.bin` to `ICON/TITLE.BIN`.
3. **ESC**, on the **animation** screen: **Ctrl+F10** → copy to `ICON/ANI.BIN`.
4. Or: `make install-intro` if you name dumps as below.

```bash
# example after hotkey dumps exist:
cp screen_dumps/ICON_gXXXX_m01_..._title.bin  TITLE.BIN
cp screen_dumps/ICON_gXXXX_m01_..._ani.bin    ANI.BIN
```

`TITLE.BIN` / `ANI.BIN` are raw **mode 01h** pages: **2000 bytes** (40×25×2 char,attr).

## Build / install

```bash
cd games/icon-quest-for-the-ring/dummy
make && make install
make install-rt      # STAMPS.BIN + MAPRT.BIN for byte-id terrain
# make install-intro # optional: seed TITLE/ANI from latest m01 dumps
```

## Run (from `ICON/`)

```text
icon_dummy.com
```

- **ESC** — skip TITLE, then ANI; in PLAY, quit  
- **←↑↓→** — camera in PLAY  
- **R** — reset camera  

Mode-03 banners list each stage so you can see the chain even when mode 01 wipes the screen.

## PLAY terrain (unchanged)

- 19×2×6 stamps + column-39 half-stamp  
- Bank is **char,attr**; `BA.DAT` bake drops leading `5Ah`  
- Parity: `STAMPS.BIN`+`MAPRT.BIN` → exact gold B800 terrain  

## What is *not* authentic yet

| Item | Notes |
|------|--------|
| Pascal MT+ / real OVL execute | OVL is **FCB block-read only** (same rec counts as log), not jumped into |
| Title/ani generators | We **replay** captured B800 pages, not re-run ICON.EXE draw code |
| Menus / story / copy-protect | Skipped; go assets → PLAY after intros |
| Player sprites / HUD | Not drawn |

Next authenticity steps: capture full TITLE/ANI; RE ICON.EXE title paint into ASM; optional menu stubs.
