# ICON startup / dialog prompts (from binary strings)

Do **not** blindly answer `N` to every Y/N — some defaults are **Y**, and some paths need **Y**.
Hex-patch only after matching the **exact** prompt string below.

Source: `ICON.EXE` / `ICON0.OVL` / `ICON1.OVL` / `ICON2.OVL` string scan  
Y/N helper: `sub_14` with default in `AX` (`'Y'=59h` or `'N'=4Eh`) then `push` + `call`.

## Y/N questions

| Module | Prompt (ASCII) | Default key | Normal *new game → play* answer | Notes |
|--------|----------------|-------------|----------------------------------|--------|
| ICON.EXE | `Is this an IBM PC Jr` | **Y** | **N** | Early boot; wrong answer may take PCjr video path |
| ICON.EXE | `Do you want to restart a saved game` | **N** | **N** | **Y** only if loading a `.GAM` |
| ICON.EXE | `Do you want to play an advanced game` | **N** | **N** (basic) or **Y** (advanced) | Sets internal flag (`data_141`) |
| ICON1 | `Do you want to quit` | **N** | **N** while capturing | **Y** to leave play |
| ICON1 | `Do you want to use the joystick` | **Y** | **N** (keyboard) | Easy to miss — default is Y |
| ICON2 | `Do you wish to save this game` | **Y** | **N** if discarding | After quit / end |

### Save-load only (if restart = Y)

| Prompt | Input |
|--------|--------|
| `Enter the game save number (0, 1-9)?` | digit |
| `Enter the disk drive (A, B, C)?` | `A`/`B`/`C` |
| `Do you have the correct disk in the default drive?` | follow UI |
| `Did you enter the file number correctly?` | Y/N |

## Title + intro animation — **Esc only**

| Stage | What you see | Skip key | Not |
|-------|----------------|----------|-----|
| Title | Gold ring / “icon” / Macrocom | **Esc** | Space / Enter / Y-N |
| Animation | Particles / second intro after title | **Esc** | Space / Enter / Y-N |

Each screen needs its **own** Esc (two Esc presses total, with a short wait so the ani has started).  
Same rule in the dummy (`stage_title` / `stage_ani` wait for Esc).

## Space / continue (not Y/N, not Esc)

| Module | Prompt | Key |
|--------|--------|-----|
| ICON1 / ICON2 | **`Press the SPACE BAR to continue`** | **Space** |
| ICON* | `…press the Space Bar.` (original disk / F1 help) | Space |
| ICON* | `Space Bar to return to your game.` | Space (help exit) |
| ICON.EXE | `…and press the enter key. Then run ICON` | setup text, not mid-game |

Story text in **ICON0** (legend pages) is mostly `push FFFF` wait/ack style — typically advanced with **Space** (or any key) between paragraphs. There are **many** pages ending near:

- `…overcome the malign effects of the ring?`
- `Knowing the history of the ring, will` / `Siegfried have the wisdom…`  
  (narrative, **not** a `sub_14` Y/N — no `B8 4E/59` after the string)

Spam **Space** through the legend — **not** Esc (Esc is reserved for title/ani skip and later quit).

## Copy protection (not a Y/N)

| Prompt | Action |
|--------|--------|
| `This is an illegal copy of ICON` / `You should be ashamed…` | Failed disk check (`sub_93` ≠ 1) |
| `Put the original game disk in floppy drive A or B & press the Space Bar.` | Insert / Space |

For local RE dumps, prefer **pass the check** (working tree already runs) or a **targeted** patch of the `cmp ax,1` / `jne` at the illegal-copy site — not Y/N hex.

## Movement / inventory (F1 help strings in ICON1)

| Key | Action |
|-----|--------|
| **Arrows** / keypad **1–9** (not 5) | Move (8 directions on keypad) |
| **P** | **Pick up object** |
| **D** | Drop object |
| **W** | Weapon |
| **Esc** | Quit (then Y/N) |
| **F1** | HELP |
| **F2** | Sound |
| **Space** | Attack (sword / wand aim — see help) |
| Joystick btn #1 | Attack |
| Joystick btn #2 | Pick up |

## Level A: sword (player report + map)

- Hero **spawn** from `LA.DAT` / `LA.ADV` line 0: **`3 3`** (map stamp coords, stride 100).  
- At cam (0,0) live dump: hero column ~ screen **col 8**, feet row **24** (matches spawn near tile x≈3, y≈3).  
- **Sword is on the ground 6 steps south of the hero** (walk **Down** / keypad **2** ×6, then **P**).  
- Pick-up key is **uppercase `P`** (ICON1 `cmp ax,50h` → `sub_135`); lowercase may be ignored.  
- Live: hero can show **arm reach** without taking the item if not on the object tile / not ready — stand still and press **P** again (no Space/attack).  
- **Bat hit** → triangle goes **yellow** (`attr 8Eh` = blink+yellow). Flash is short — dump F10 immediately when hit.  
- Level A has **rats** and **bats** near spawn / south path (MA.DAT: Bat 0/1, Rat left/right).  
- Automation: hold-move south; try **P** on last steps + while standing; avoid F10 between early steps.  
- Sword is a **sprite object** (DR `sword`), not a MAP stamp.  
- `LA.DAT` pairs after count `4` still *hypothesis*.

```bash
SWORD_SOUTH_STEPS=6 GET_SWORD=1 MOVE_GAP=0.55 ./auto_icon.sh damage-capture
```

## Suggested key script: new game → overworld (keyboard)

Order matches typical boot (confirm against live if a step is skipped when flag already set):

1. **`n`** — `Is this an IBM PC Jr` (default was Y!)  
2. **Esc** — skip **title** (not Space)  
3. **Esc** — skip **animation** (second Esc after ani is on screen)  
4. **`n`** — restart saved game?  
5. **`n`** — advanced game? (or **`y`** if you want advanced)  
6. **Space** × many — story / **Press the SPACE BAR to continue**  
7. **`n`** — joystick? (default was Y!)  
8. Play…  
9. Quit path: **Esc** → **`y`** quit → **`n`** save  

Automation:

- **xdotool path:** `ICON/auto_icon.sh to-play` (see script comments).
- **Control-socket path (preferred):** `ICON/live_agent.py` — no window focus; talks to `[controlsocket]` at `/tmp/dosbox-control.sock`.

```bash
cd games/icon-quest-for-the-ring/ICON
./live_agent.py                    # start DOSBox, to-play + sword, leave running
./live_agent.py --attach           # use already-running DOSBox
./live_agent.py --wander 20        # after sword, roam + Space attack
./live_agent.py --to-play-only     # stop at overworld
printf 'TEXT\nQUIT\n' | nc -U /tmp/dosbox-control.sock
```

**Verified 2026-07-20:** xdotool path reached level A overworld; F10/F11 dumps landed (`g0011`).  
**Verified 2026-07-20:** `live_agent.py` over socket reached overworld TEXT terrain + sword south×6+P sequence (DOSBox left running).

## Hex-patch policy (if used later)

| Goal | Safe approach |
|------|----------------|
| Always “no restart / no advanced” | Patch only those two `call sub_14` sites after the matching strings |
| Always “not PCjr” | Force **N** result on the PCjr site only (default is Y) |
| Always keyboard | Force **N** on joystick site (default is Y) |
| Skip copy-protect | Patch check at illegal-copy branch only |

**Do not** replace every `sub_14` with `xor ax,ax` — that would break “quit=Y”, “save=Y”, and PCjr handling.
