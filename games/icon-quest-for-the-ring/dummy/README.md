# ICON dummy loader (v7)

DOS COM that mirrors **ICON.EXE load staging** in assembly, then runs the
proven terrain play loop. Not a full Pascal MT+ reimplementation — same
**order of modes, FCB names, and ESC-skippable intros**, then PLAY.

**v6:** file-mode `BA.DAT` bake + `LA.MAP` RLE = runtime terrain parity.  
**v7:** hero pose from live overworld dump; keys **1–4** = ok / hurt / crit / dead.

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
# control socket (no xdotool)
printf 'DUMPSCREEN\nQUIT\n' | nc -U /tmp/dosbox-control.sock
```

(Same `windowmap windowactivate --sync` chain as a working feh loop.)

```bash
cd games/icon-quest-for-the-ring/ICON

# Title ring: spam Ctrl+F10, pack TITLES.BIN
./auto_icon.sh title-frames

# Particles: ESC title, spam Ctrl+F10, pack ANIS.BIN
./auto_icon.sh ani-frames

# Skip menus to overworld + optional F10/F11 dumps
# (answers: STARTUP-PROMPTS.md — some defaults are Y, not N)
./auto_icon.sh to-play
# QUIT=0 STORY_SPACES=40 ./auto_icon.sh to-play
# PNG filmstrip (real pixels): capture/filmstrip_*/  via Ctrl+F5/Alt+F5
# PNG_SHOT=1 SHOT_HOST=1 GET_SWORD=1 ./auto_icon.sh damage-capture

./auto_icon.sh kill    # Ctrl+F9 + SIGTERM
```

Env knobs (defaults are already high for speed):

```bash
CYCLES=100000          # fixed cycles (was 3000 interactive)
TITLE_FRAMES=8
ANI_FRAMES=8
FRAME_GAP=0.25         # host delay between F10 dumps
BOOT_WAIT=2.0          # after focus settle
ANI_WAIT=4.0           # after ESC title, wait for particles
```

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
- **1 / 2 / 3 / 4** — hero ok / hurt (yellow ▼) / critical (red ▼) / dead  
 
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
