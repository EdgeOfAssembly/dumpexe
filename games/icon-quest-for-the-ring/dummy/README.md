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

## Capture multi-frame title / ani (automated)

Script focuses DOSBox by **PID** (title becomes `ICON.EXE ...` after start):

```bash
pid=$(pgrep -x dosbox)   # or /tmp/auto_icon_dosbox.pid
xdotool search --pid "$pid" windowmap windowactivate --sync key ctrl+F10
```

(Same `windowmap windowactivate --sync` chain as a working feh loop.)

```bash
cd games/icon-quest-for-the-ring/ICON

# Title ring: spam Ctrl+F10, pack TITLES.BIN
./auto_icon.sh title-frames

# Particles: ESC title, spam Ctrl+F10, pack ANIS.BIN
./auto_icon.sh ani-frames

# Skip menus to overworld + optional F10/F11 dumps (see ICON_gameplay.txt)
./auto_icon.sh to-play

./auto_icon.sh kill    # Ctrl+F9 + SIGTERM
```

Env knobs: `CYCLES=30000 TITLE_FRAMES=8 ANI_FRAMES=6 FRAME_GAP=0.3 BOOT_WAIT=1.2`

Manual pack (if you already have hotkey dumps):

```bash
cd ../dummy && make install-title-frames   # or install-ani-frames
```

Only `reason=hotkey` metas are packed (max 8 frames). Dummy **loops** until **ESC**.

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

## What you should see vs ICON.EXE

| Stage | Expected in dummy | Not yet |
|-------|-------------------|---------|
| TITLE | Same **B800 page** as your Ctrl+F10; needs `icon_mode_01` (8×8 font + CRTC) | Regenerating title in ASM |
| ANI | **One frozen frame** of the particle screen | Moving animation loop |
| PLAY | Terrain map (parity tables / BA+MAP) | Hero, monsters, HUD, combat |

If title still looks like “half ring + garbage”, the dump is fine but **video init** was wrong — rebuild with current COM (`icon_mode_01` mirrors ICON.EXE ~`1DF8`).

## What is *not* authentic yet

| Item | Notes |
|------|--------|
| Pascal MT+ / real OVL execute | OVL is **FCB block-read only** (same rec counts as log), not jumped into |
| Title/ani generators | We **replay** captured B800 pages, not re-run ICON.EXE draw code |
| Animation motion | Single frame in `ANI.BIN` |
| Menus / story / copy-protect | Skipped; go assets → PLAY after intros |
| Player sprites / HUD / mobs | Not drawn |

Next: multi-frame ANI if desired; sprite layer; optional menu stubs.
