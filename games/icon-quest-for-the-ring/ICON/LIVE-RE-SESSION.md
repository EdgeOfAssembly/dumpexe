# LIVE RE session notes (gameworld + machine)

Play is only a **probe** for reverse-engineering. Prefer: observe → act one step → settle → screenshot → dump → pause → note.

Session time: **2026-07-20** (DOSBox pid 16948, gen **g0019**, mode 01h 40×25).

Artifacts: `/tmp/icon_shots/re_session/`  
Log append stream also in this file from the automated run.

---

## 1. World inventory (what is on screen)

| Visual | Identity (working) | Evidence |
|--------|--------------------|----------|
| Cyan blade in hero hand | **Sword equipped** | Earlier ground sword gone after on-tile **P**; DR label `sword` |
| Small yellow/brown stack (lower open floor) | **`gold`** (DR) | DR.DAT string `gold`; coin-pile art; not MAP stamp |
| Same art (upper-right open floor) | **`gold`** (2nd pile) | Same sprite |
| Red/blue `+` | **Bats** | MA.DAT `Bat 0` / `Bat 1`; earlier combat notes |
| Not seen this session | Poison_Mushroom, rats | MA.DAT has them; may be off-camera / not spawned |

**DR.DAT labels (strings):** `gold`, `sword`, `magic sword`, `broken sword`, `white mushroom`, `Poison_Mushroom 0/1`, …

---

## 2. Level A static data cross-links

### `LA.DAT` (ASCII, CRLF, ends `1Ah`)

```
3 3          # hero spawn tile (confirmed)
2 2
2880 2400
14 20
25
4            # object count? (hypothesis)
3 10
-1
27 2
11 54
94 95
25 88
-1
-1
-1
-1
86 67
```

### `LA.ADV` (related; different tail)

Similar header; object section uses more `-2` / `-1` fillers; ends `86 67`.

### `MA.DAT`

Monster/item **names + numeric params** (not positions): Bat, Rat left/right, Poison_Mushroom, Kobold, Alligator, …

**Open RE questions**

1. Which `LA.DAT` pairs are **(tile_x, tile_y)** for the two gold piles vs sword vs other?
2. Is count `4` four ground objects (sword + 2×gold + ?)?
3. Where is the **runtime object table** in DS (not covered by default mem_dump stamps/map/offscr)?

---

## 3. Machine-code / dump pipeline used

| Tool | How |
|------|-----|
| Host pause | **Alt+Pause** → title `[PAUSED] ICON.EXE…` (Staging host pause) |
| Unpause | Alt+Pause again |
| Screen dump | Control socket `DUMPSCREEN` → `screen_dumps/ICON_g0019_…` |
| Mem dump | `DUMPMEM` → map @ phys `11424` size `0F00`, offscr @ `0E37C` size `2000` |
| B800 | Socket `B800` → `*_b800.hex` (40×25×2 = 2000 bytes) |
| Keys | Socket `KEY` / `KEYDOWN`/`KEYUP` (US layout); **uppercase P** for pickup |
| Trace | `game_trace.log` — INT 15h AH=4Fh with **AL=50h** = scancode for **P** seen |

Default dump **regions did not capture score/inventory/object list** (see §4).

---

## 4. Pickup attempts (2026-07-20) — negative result is useful

### Item A (lower gold)

- Approach: down ×2, left ×2, settle, **P** ×5.
- **After shot:** lower gold **still present**; upper gold still present.
- Pause title confirmed: `[PAUSED] ICON.EXE…`

### Item B (upper gold)

- Path wandered (up/right); **B_before_P** still shows **both** golds; hero **not** on upper gold tile.
- **P** ×5 → golds **still** on ground.

### Diffs (machine)

| Pair | Result |
|------|--------|
| A map before/after | **IDENTICAL** 3840 B |
| A offscr before/after | **IDENTICAL** 8192 B |
| A B800 before/after | **IDENTICAL** 4000 B |
| B map / offscr / B800 | **IDENTICAL** |

**Interpretation**

1. **P did not complete a successful pickup** (not on object tile / reach anim only). Matches STARTUP-PROMPTS: arm-reach without item if not on tile.
2. Even on success, **current mem_dump regions may be wrong** for score/object flags — need DS scan for score / “carrying” strings / object slots.
3. **INT 15h/4Fh AL=50h** proves **P scancodes reached the guest** (input path OK).

### Trace crumbs (P keys)

```
INT 15h AH=4Fh AL=50h   # keyboard intercept, scancode 50h = 'P'
```

ICON1 pickup: **`cmp ax,50h` → `sub_135`** (prior RE). Live confirmation of scancode delivery only, not of `sub_135` success.

---

## 5. Key artifact paths (this session)

```
/tmp/icon_shots/re_session/
  022316_00_baseline.png
  022335_A_after_P.png          # gold still down
  022338_paused_A_gold.png      # [PAUSED]
  022412_B_before_P.png
  022419_B_after_P.png
  022421_paused_B_gold.png
  00_baseline_b800.hex
  A_before_P_b800.hex / A_after_P_b800.hex   # identical
  B_before_P_b800.hex / B_after_P_b800.hex   # identical
  *_mem_dumps_ICON_mem_g0019_map_*
  *_mem_dumps_ICON_mem_g0019_offscr_*
  *_screen_dumps_ICON_g0019_*

ICON/LIVE-RE-SESSION.md          # this file
ICON/game_trace.log              # g0019 run
```

---

## 6. Agent RE toolkit (fork)

After rebuild with agent_re:

```text
BP pick  ????  → BPINT pick INT 21 AH=??
WATCH attr ds:????+1 pause
SNAPSHOT before_p
… KEY P …
SNAPSHOT after_p
DIFF before_p after_p
TRACEBACK 128
INTRING 32 json
```

## 7. Next RE steps (ordered)

1. **On-tile gold pickup** + `SNAPSHOT`/`DIFF`/`TRACEBACK` around **P**
2. **WATCH** candidate object/score DS ranges after Sourcer hit on `sub_135`
3. **Map `LA.DAT` pairs → tiles** using grid overlay step counts
4. **Update `icon_dummy.com`** with confirmed gold/object rules once diffs prove them
---

## 7. Process rules (agent + human)

| Rule | Why |
|------|-----|
| Focus DOSBox before shot | Avoid wrong window / empty grab |
| Settle ≥1.2s after move | ICON step latency |
| Long KEYDOWN (~0.7–1.2s) for walk | Short holds often no step |
| Screenshot when unsure | TEXT loses sprites |
| Dump + **Alt+Pause** after each real state change | Machine + human inspection |
| Uppercase **P** / **N** | Game compares full AX / shifted keys |
| Log world **and** file paths | Dual notebook: gameworld + machine |
| **Host grid overlay** (`[debugoverlay]`, `OVERLAY on`, Ctrl+Alt+G) | Count text cells on screenshots; **never** in B800/mem dumps |

---

## 8. Session outcome (honest)

| Goal | Status |
|------|--------|
| Identify other ground items | **gold** ×2 (DR); bats; sword already held |
| Pick them up | **Not confirmed** — still on floor |
| Pause after each pick | Pause works; used after P attempts |
| Machine dumps | Collected; **no delta** in map/offscr/B800 → need better regions + true on-tile pick |

**Primary RE win this session:** dual-notebook workflow + artifact set + proof that default dump windows miss inventory/score + P scancode path live.

## Grid pathfind sword 2026-07-20T02:39:58
Overlay 40x25 host grid ON (OpenGL). Goal: stand on sword, P, dump, pause.
SHOT /tmp/icon_shots/re_grid/023958_00_spawn.png (68084B)
south step 1 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024001_south_1.png (68066B)
south step 2 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024003_south_2.png (68066B)
south step 3 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024005_south_3.png (68066B)
south step 4 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024008_south_4.png (68066B)
south step 5 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024010_south_5.png (68066B)
south step 6 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024013_south_6.png (68066B)
south step 7 hold=0.5s
SHOT /tmp/icon_shots/re_grid/024015_south_7.png (68253B)
P 1
P 2
P 3
P 4
SHOT /tmp/icon_shots/re_grid/024021_after_P.png (68253B)
OK
OK
paused title='[PAUSED] ICON.EXE - 100000 cycles/ms - to capture the mouse press Ctrl+F10 or click any button'
SHOT /tmp/icon_shots/re_grid/024022_paused_after_sword.png (67870B)
SHOT /tmp/icon_shots/re_grid/024023_final.png (67861B)
done sword pathfind sequence

---

## Night session 2026-07-20T03:38–03:50 (agent RE toolkit live)

### Tooling proven

| Feature | Result |
|---------|--------|
| `controlsocket` KEY/KEYDOWN | Works; no xdotool |
| `OVERLAY on` 40×25 | Works (OpenGL path) |
| `SNAPSHOT` / `DIFF` | Works; packs under `ICON/re_snaps/<tag>/` |
| `TRACEBACK` / `INTRING` | Works; INT 15h AH=4Fh scancodes live |
| `WATCH ds:OFF+SZ` | Arms; phys ranges resolve from live DS=0E25 |
| `BP CS:IP` | **Broken for bare `01AD:4B4F`** — lowercased → octal parse fail. Use `0x1AD:0x4B4F` (fixed in fork `parse_hex_u16`) |
| `CLEAR` | Did **not** clear sticky `g_last_trap` (fixed in fork) |
| `BPINT 16` | Parsed as **decimal** → INT 10h. Use `0x16` |
| CAPTURE rendered | Filmstrip under `capture/` + `/tmp/icon_shots/tonight/` |

### Sourcer (subagent) — pickup + LA.DAT (high confidence)

**Pickup chain (ICON1 CS offsets):**
```
4AF0  key |= fold: if >= 'a' then AND 5Fh   ; p→P
4B1A  cmp 20h → Space attack (sub_122)
4B4F  cmp 50h → P
4B57  call sub_17  → body @1549  (AABB scan, real pickup)
4B5A  call sub_135 → body @503E  (equip bookkeeping if 2C1A+96h == FFFE)
```

**LA.DAT (basic game):**
| Field | Value | Meaning |
|-------|-------|---------|
| spawn | `3 3` | tile |
| origin | `2880 2400` | world |
| line 5 | **`4`** | **gold quota** (`DS:5A24`), NOT object count |
| slot 91 | **`3 10`** | **sword** (type `DS:810A`) |
| slots 93–96 | coords | red wand / blue wand / armor / shield |
| slot 101 | `86 67` | Icon marker coords |

Gold piles are **ICON1 mass-init** (type `DS:2BEA`, counter `DS:2BEC`), not DAT pairs.

### Live play

- to-play + overlay + south path: sword remains on ground in **rendered** shots.
- B800 / SNAPSHOT B800: **hero only** among sprites; sword/gold/rats **absent** from page-0 dumps (INT 10h AH=05 page flips observed).
- INT 15h `AL=19h` (P make) / `2Ah` (shift) delivered; pickup still not confirmed in DS/B800 (not on-tile AABB and/or wrong dump page).
- Hero always B800 col8 rows20–24 even when visual is mid-screen → camera/page vs dump mismatch.

### Dummy v8

Updated `dummy/icon_dummy.asm` + rebuilt `icon_dummy.com`:
- Ground sword/gold (visual approx), **P** pick when steps_south≥6, **G** gold demo, HUD `G:n/4` + `S` if equipped.
- Comments document Sourcer DS tables / LA.DAT facts.

### Fork fixes landed (need rebuild+install for agent_re)

1. `parse_csip` → always-hex (`01AD:4B4F` works after lower)
2. `AgentRe_ClearAll` clears `g_last_trap`

### Artifacts

```
/tmp/icon_shots/tonight/          # rendered filmstrip
ICON/re_snaps/                    # SNAPSHOT packs
ICON/LIVE-RE-SESSION.md           # this notebook
```

---

## Night cont. 2026-07-20T03:55 (post-install hex BP fix)

### BP hex fix verified
```
BP pick 01AD:4B4F → OK   (no longer ERR bad CS:IP)
```

### Successful sword pickup (visual)

| Shot | Sword on ground? |
|------|------------------|
| `11_s7` | **yes** (below hero) |
| `11_s12` / `12_after_p` | **no** — ground clear |

Hero walked south ×12 (hold 1.3s) without BPs armed during walk (BPs mid-step freeze movement). Sword vanished by step 12.

Hypothesis: Down scancode **0x50** collides with ASCII **'P'=0x50** in key path — pickup may fire during walk when on-tile. Or steps 8–12 finally sat on tile and a prior buffered P completed.

### Live BP hit
```
trap=BP key at 01AD:4B4F   # after KEY p, try 4
```
Proves ICON1 key dispatch CS=**01AD** IP=**4B4F** is real at runtime.

### Sticky trap issue (fixed in fork, needs rebuild)
`CONTINUE` did not clear `g_last_trap` → LIST showed old BP forever. Fix committed: clear on CONTINUE.

### Policy for agent loops
1. **Walk with NO execute BPs** (pause freezes mid-step).
2. Arm BP/WATCH only when standing still for P.
3. Prefer visual CAPTURE to confirm ground objects (B800 misses sword sprites).
4. `SWORD_SOUTH_STEPS` live ≈ **10–12** long holds, not just 6.

Artifacts: `/tmp/icon_shots/tonight2/`
