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

## 6. Next RE steps (ordered)

1. **On-tile gold pickup (visual closed loop)**  
   One step at a time until hero **overlaps** gold in screenshot → **one P** → shot → dump → pause.  
   Do **not** spam P from a distance.

2. **Expand mem dumps** after a *confirmed* pickup  
   - Score / vitality UI area in B800 (if any) or offscreen HUD.  
   - Search DS for object-active flags vs `LA.DAT` pair list.  
   - Diff `sub_135` side effects (instruction log around pick if `trace_instructions` briefly on).

3. **Map `LA.DAT` pairs → world tiles**  
   Spawn `3 3` known; measure gold positions in stamp coords from screen + camera; match pairs.

4. **Distinguish gold vs score**  
   Does gold go to **inventory** (D drop list) or only **score**? Open inventory UI after successful pick (not accidental D).

5. **Bats**  
   Same method: approach, Space, dump hurt attr `8Eh` on triangle (known).

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
