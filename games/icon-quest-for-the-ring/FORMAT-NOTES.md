# ICON data formats (working notes)

Inferred from on-disk files + `dumpexe --cfg-interesting` load graph + live DOSBox.  
Mark unsettled claims with *hypothesis*.

## Video mode — **confirmed**

Gameplay is **BIOS text mode 01h** (40×25 color text), not a CGA graphics mode.

DOSBox Staging display log during play (2026-07-17):

| Mode | Geometry | Notes |
|------|----------|--------|
| `03h` | 720×400 text | Boot / menus / quit |
| `01h` | **360×400** text | Main play (40 cols; VGA 9×16 cells → 360×400) |
| (same 40-col) | 360×200 | Brief CRTC/page toggles mid-play |

Also confirmed in `game_trace.log`: repeated `INT 10h AH=00 AL=01`, and many direct **`B800:`** fills.

Implications:

- Visible playfield = **40 columns × 25 rows** of **char + attribute** words at `B800:0000` (80 bytes/row, 2000 bytes on screen).
- Terrain art is **CP437 block characters** (`░▒▓│─┌` / half-blocks `▀▄▌▐` / etc.) plus CGA attributes — classic “text-mode graphics.”
- Sprites (player, bat, sword) are drawn into the same text cell grid (or as 2×2 cell stamps), not planar bitmap sprites.
- `BA.DAT` is a **tile bank of precomposed char/attr cells**, not a 1bpp font bitmap.

Screenshot (`/tmp/ICON.png`) matches this: gray floor, green checker walls, red brick platforms, purple/black slopes — all half-block / shade-char art.

## Naming

| Pattern | Role |
|---------|------|
| `L[A–G].MAP` | Level tilemap (binary) |
| `L[A–G].ADV` | Level parameters (ASCII CR/LF, optional trailing `1Ah` padding) |
| `L[A–G].DAT` | Level object/placement params (ASCII, same family as ADV) |
| `M[A–G].ADV` / `.DAT` | Monster/entity tables (ASCII names + numbers) |
| `BA.DAT` / `BB.DAT` | Terrain tile banks: char/attr cell stamps for mode 01h (2304 B each) |
| `DR.DAT` / `SP.DAT` | Sprite banks with embedded length-prefixed labels |
| `icon0.ovl`… | Chain overlays (full MZ images) |
| `ICON#.GAM` | Save games (FCB; README needs `FCBS=10`) |

Game builds names as **extensions** (`.dat` / `.adv` / `l?.map`) plus level letter — see CFG seeds `1BCA`, `1BE2`, `1BF7`.

## Level ADV (`L*.ADV`) — *hypothesis* (+ one confirmed field)

Text lines, numbers space-separated, ends with `1Ah` EOF padding on some files.

Observed skeleton (LA / LB / …):

| Line | Example (LA) | Guess |
|------|----------------|-------|
| 0 | `3 3` | Start / spawn tile or cell coords |
| 1 | `2 2` | Secondary point or camera |
| 2 | **`2880 2400`** | **Confirmed world origin** (ICON1 subtracts `0xB40`/`0x960` then `/ 0x120`) |
| 3 | `14 20` | Logical map size or room grid (not raw MAP byte dims) |
| 4 | `250` | Timer / darkness / resource scalar |
| 5 | `8` | Count of following link records? |
| 6… | `3 10`, then many `-1` / `-2` | Exit/warp table (negative = none / special) |
| last | `86 67` | Checksum-ish or color pair |

LB uses negatives on line 1 (`-158 -250`) → signed 16-bit fields, not only grid indices.

World → stamp coords (ICON1 @ `9B27`):

```
tile_x = (world_x - 2880) / 288    ; 0x120 = 288
tile_y = (world_y - 2400) / 288
```

## Tile bank `BA.DAT` / `BB.DAT` — **confirmed shape**

| Property | Value |
|----------|--------|
| Size | 2304 bytes (`BA` loaded at level start; `BB` not opened in first playthrough) |
| Stamps | **96** × **24** bytes |
| Stamp geometry | **2 cells wide × 6 cells tall** (ICON1 draw @ `2D9A`: `cx=6`, each iter `movsw; movsw`, row stride `0x50`) |
| On-disk packing | **`attr, char`** pairs (odd bytes = CP437 `0xDE/B1/B0/0x83/…`) |
| Runtime B800 | Live dumps prove **`char, attr`** (even=char, odd=attr) at `B800:0000` |
| Runtime | Stamp source `DS:207A + tile_id * 24` → blit (`movsw`) into text buffer; **byte-swap vs BA on disk** when writing B800 |
| Tile id range | Map uses lo7 **0..90** (fits 96 stamps) |

Preview: `map_preview/BA_stamps_2x6.png`  
Decoder: `decode_map.py`

### Live VRAM dumps (DOSBox `screen_dump`) — **confirmed 2026-07-17**

Mode **01h** play dumps are exactly **2000 B** = 40×25×2 at phys **`0xB8000`**.

| Dump | Contents |
|------|----------|
| `…0002` | Title / “restart saved game?” dialog (box drawing + ASCII) |
| `…0005` / **`…0006` (hotkey)** | **Gameplay** — green `░` walls, red brick, gray floor, player as multi-cell glyph column |
| `…0008` | Mode **03h** shell `C:\>` after quit |

Gameplay terrain chars (live `…0006`):

| Char | Count | Role |
|------|-------|------|
| `0xDE` (▐) | ~477 | gray floor / open (`attr` often `0x77`) |
| `0xB1` (▒) | ~241 | green checker wall (`attr` `0x02`) |
| `0x83` | ~174 | red brick-ish (`attr` `0x04`) |
| `0x00` | ~103 | black void / border |

Player (column x=8, rows 20–24): chars `02 2A 09 12 1F` with colored attrs — **sprite stamped as text cells**, not MAP tiles.

Decode tool:

```bash
python3 games/icon-quest-for-the-ring/decode_screen_dump.py
# → map_preview/b800_ICON_….png
```

### BA stamp geometry (refined from live dump)

| Evidence | Conclusion |
|----------|------------|
| Exact 2×2 windows on `…0006` | **288** sequential **2×2** cells in `BA.DAT` (8 B each, on-disk `attr,char`) match solid terrain |
| Solid stamp IDs on screen | **283** = all `DE/77` floor, **197** = all `B1/02` green, **188** = all `83/04` red |
| Char-only 2×6 windows | Also match BA as **96** stamps of 2×6 (24 B) for solid fills (ids 0/10/11/12/14…) |
| ICON1 draw @ `2D9A` | Still **2×6** `movsw` loop from `207A + id*24` — runtime table may be built from BA |

Attrs on screen can differ from BA defaults (lighting / recolor); **characters** are the stable key.

### MAP → stamp draw (ICON1) — **confirmed path**

```
tile_x = (world_x - 2880) / 288      ; DS:822C
tile_y = (world_y - 2400) / 288      ; DS:8230

; horizontal strip, i = 0..0x12 (19 stamps):
screen_col = (i << 1) + 1           ; 1,3,5,...,37   (c2f7 = SHL)
screen_row = row_arg * 6 + 2        ; 2,8,14,20       (strip calls)

map_byte = [DS:31D4 + (tile_x + i) * 100 + (tile_y + row_arg)]
SI       = DS:207A + map_byte * 24  ; NO lo7 mask — full byte is stamp index
call draw_2x6                       ; 2D9A: 6 rows × 2× movsw
```

Implications:

| Item | Value |
|------|--------|
| MAP stride | **100** on X (`width≈38`, `height=100` for LA 3800 used) |
| Stamp id | **full MAP byte** (0..180 observed) |
| Bank size | `BA.DAT` alone = 96 stamps; **BA‖BB = 192** covers max id 180 |
| Viewport | **19×N** stamps; col phase **1**, row phase **2** |
| Scroll | Off-screen text buffer; ±6 rows (`0x1E0` bytes) memmoves |

Stamp examples (chars only; attrs recolored live):

| Id | Pattern | Role |
|----|---------|------|
| 0, 12 | all `DE` | floor |
| 10, 14 | all `B1` | green wall |
| 11 | all `83` | red brick |
| 130+ | mixed DE/B1/B0 | edge / transition (BB range) |

### MAP ↔ live dump `0006` — *partial*

Direct blit of `map_byte → BA‖BB stamp` at fixed phase peaks ~**44%** char match over the viewport (best ~`(7,75)`). Majority-vote **learned** MAP→stamp tables at other origins reach ~**82–87%** but look overfitted (MAP `0` not stably “floor”).

Likely remaining gaps:

1. Runtime stamp table at `207A` may not be a raw `BA‖BB` concat (remap / bake step).
2. Visible B800 is a **scrolled window** into a taller buffer — dump may not be stamp-grid aligned the way a cold camera is.
3. Sprites (player column) and HUD overwrite terrain cells.

Decoder: `decode_map.py` (full map + `--camera X,Y` viewport).

```bash
python3 games/icon-quest-for-the-ring/decode_map.py LA --camera 7,75
```

### Live DS dumps (DOSBox `mem_dump`)

With `mem_dump = true` (see `ICON/dosbox-staging.conf`), **Ctrl+F11** writes guest regions while ICON is running:

| File stem name | Default region | Purpose |
|----------------|----------------|---------|
| `…_stamps_…` | `ds:207A+1200` | Runtime stamp bank (192×24 B) |
| `…_map_…` | `ds:31D4+0F00` | MAP index table (LA size) |
| `…_offscr_…` | `ds:206C->near+2000` | Follow near ptr @ `DS:206C` → offscreen text buffer |

Outputs go under `mem_dumps/`. **Priority:** feed `STAMPS.BIN` / `MAPRT.BIN` into `dummy/` (see `dummy/README.md`) and match B800 there — do **not** block on file→PNG.

### Working order (agreed)

1. **Dummy draw path in ASM** (map index → stamp → B800) until terrain is byte-identical or sprite-only deltas.
2. **Then** host PNG / disk tools that reuse the same blit rules.
3. Load-time bake (`LA.MAP`→`31D4`, `BA.DAT`→`207A`) only when file-mode fidelity needs it.

**Parity result (mem dump g0013 + B800 `…0008`):** 19 full stamps + col-39 half-stamp; **100% terrain** bytes; remaining diffs = player sprite (bottom, cols 7–9).  
**BA.DAT note:** leading `5Ah` then char,attr stream matches runtime stamps **0..90** when the header byte is dropped.

## Level MAP (`L*.MAP`) — **strong** (index formula confirmed)

| File | Size | Notes |
|------|------|--------|
| LA | 3840 | live FCB: 30×128 exact, no compression |
| LB | 4224 | |
| LC | 3712 | |
| LD | 4224 | |
| LE | 4096 | |
| LF | 4736 | |
| LG | 3840 | |

### Index formula (ICON1, many call sites)

```
addr = DS:31D4 + tile_x * 100 + tile_y
tile_id = mem[addr]          ; then stamp at 207A + (tile_id * 24)
; graphics index uses low 7 bits in practice (max lo7 = 90)
; bit 7 = flag; collision probes treat id <= 9 as special / walkable-ish
```

For **LA.MAP** (3840 B): **38 × 100** stamps with stride 100 (`38*100=3800`), short tail often `0x1A`-ish padding.

Viewport draw loops **0..0x12** (19 stamp columns) × 2 cells = 38 cells ≈ full 40-col width with margins. Vertical stamp step = 6 text rows.

### Not a B800 dump

~20% zeros; ~33% high bit; values 0–180 only; **no** `0xDE/B0/B1` in MAP bytes.

### Decode tool

```bash
python3 games/icon-quest-for-the-ring/decode_map.py LA BA
# → map_preview/LA_decoded.png  (38×100 stamps, 608×4800 px at 8×8 cells)
# → map_preview/LA_viewport.png (19×5 dense crop)
# → map_preview/BA_stamps_2x6.png
```

**Still open:** exact on-screen camera origin matching `/tmp/ICON.png` pixel-for-pixel (scroll offset + which BA vs BB bank); whether raw ids > 127 select a second bank or only set the flag.

## Monster ADV (`M*.ADV`)

ASCII records. Pattern per creature (*hypothesis*):

```
count? or type id
name_frame_0
name_frame_1
...
numeric fields (HP, scores, flags, animation ids)
```

Example names: `Bat 0`, `Rat left`, `Poison_Mushroom 0`, `Snake left 0`, …  
Scores like `8000` / `6500` match combat tables.

## Sprites `DR.DAT` / `SP.DAT`

Length-prefixed ASCII labels interleaved with binary frames (`health bar`, `man front`, `magic sword`, …).  
SP is a superset/variant of DR (more creatures/FX).

## I/O map (live DOSBox FCB log — 2026-07-17 run)

Gameplay: skip intros → no save → no advanced → story → level A play → death → quit, no save.  
Conf: slim debugtrace + **FCB logging** (`trace_file_io`).

### Confirmed FCB OPEN order (level start)

| Time (approx) | File | How read |
|---------------|------|----------|
| T+90s | **ICON0.OVL** | FCB OPEN + **BLOCK-READ** 243×128 (=31104 B; file is 31744) → DTA@phys `01B70` |
| T+91s | **BA.DAT** | OPEN + 18× sequential READ 128 B (full 2304 B) → DTA@`1681F` |
| T+98s | **LA.MAP** | OPEN + **30×** sequential READ 128 B (=**3840** B exact) → DTA@`1681F` |
| T+108s | **LA.DAT** | OPEN + sequential READ |
| T+109s | **MA.DAT** | OPEN + sequential READ (ASCII monsters; matches on-disk) |
| T+111s | **ICON1.OVL** | OPEN + BLOCK-READ 399×128 (=51072; file 51712) |
| T+756s (quit UI) | **ICON2.OVL** | OPEN + BLOCK-READ 183×128 (=23424; file 24064) |

FCB always at **`0E2F:8508`** for open; block-read sometimes uses **`0E2F:005C`**.  
First **LA.MAP** DTA dump **byte-identical** to `LA.MAP` on disk (no on-disk compression).

Not opened in this play: `LA.ADV`, `SP.DAT`, `BB.DAT`, `DR.DAT`, other levels.

Overlay chain (confirmed live):

```
ICON.EXE → ICON0.OVL (boot/menu assets path) → BA.DAT + LA.* + MA.DAT → ICON1.OVL (gameplay)
         → ICON2.OVL (quit/save UI)
```

### Static CFG anchors (still valid)

```
1CC6/1CE8  path:icon0.ovl
1BF7       path:l?.map
7A77/7A84  set-DTA + FCB AH=27 @ DS:5C helper
```

## How to extend

```bash
# Seeds + reverse caller chains
./dumpexe --cfg-interesting --cfg-no-insns --cfg-load-depth=8 \
  games/icon-quest-for-the-ring/ICON/ICON.EXE | less

# Break when FCB block-read runs (name already in DS:5C)
./dumpexe --simulate --max-insns=2000000 \
  --bp=int:21,ah=27 --dump=ds:5c:25 \
  games/icon-quest-for-the-ring/ICON/ICON.EXE
```

Then dump DS:005C FCB name field after hit to see `LA.MAP` / etc.
