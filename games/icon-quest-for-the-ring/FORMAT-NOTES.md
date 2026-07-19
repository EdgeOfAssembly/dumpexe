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

## Tile bank `BA.DAT` / `BB.DAT` — **confirmed shape + bake**

| Property | Value |
|----------|--------|
| Size | 2304 bytes each |
| On-disk layout | **`byte0 = stamp count N`**, then **`N × 24`** bytes of **`char, attr`** cells (already B800 order) |
| BA example | `N = 0x5A` (90 stamps) → 2160 B payload; rest of file unused |
| Stamp geometry | **2×6** cells (ICON1 **`sub_83` @ `2B9A`**) |
| Runtime @ `DS:207A` | Packed stamps only (no count byte); ids **0..N−1** |
| B800 | same **`char, attr`** words via `movsw` (no swap) |

> Older notes claimed on-disk `attr,char` + swap — **wrong**. `5A DE 77 DE 77…` is count + `DE/77` floor cells.

### ICON0 bake (`sub_32` / ~`0B17`…`0B94`) — **confirmed**

```
stream = open("?.DAT")           ; BA/BB via Pascal MT+ stream @ DS:2A5A
N = getbyte(stream)              ; sub_253
for stamp_id in 0 .. N-1:
  for cell in 0 .. 11:           ; 12 words
    lo = getbyte(stream)         ; char
    hi = getbyte(stream)         ; attr
    word = (hi << 8) | lo        ; sub_287 shl 8 + or  → memory [char,attr]
    [DS:207A + stamp_id*24 + cell*2] = word
```

Live `STAMPS.BIN[0:2160] == BA.DAT[1:2161]` (100%). Dummy `bake_stamp_file` implements this.

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
| ICON1 **`sub_83` @ `2B9A`** | **2×6** `movsw` from `207A + id*24` into offscreen (`DS:206C`) |

Attrs on screen can differ from BA defaults (lighting / recolor); **characters** are the stable key.

### MAP → stamp draw (ICON1) — **Sourcer-confirmed** (`ICON1.LST`)

#### Hot registers / DS slots

| Slot | Role | Sourcer label / site |
|------|------|----------------------|
| `DS:31D4` | MAP index table base | `data_123`; `mov ax,31D4h` before index |
| `DS:207A` | Runtime stamp bank base | `mov ax,207Ah` then `id * 18h` |
| `DS:206C` / `206E` | Offscreen text buffer far ptr | `les di` / `add di,[206C]` |
| `DS:5DE4` / `5DE6` | Stamp far ptr into `sub_83` | set just before `call sub_83` |
| `DS:810C` | Destination **screen row** (cells) | `row*6+2` |
| `DS:810E` | Destination **screen col** (cells) | `(i<<1)+1` typical |
| `DS:822C` | Camera / tile_x | map X origin |
| `DS:8230` | Camera / tile_y | map Y origin |
| `DS:2D82` | Cached stamp id (word) | from `es:[di]` map byte |

#### Index + stamp (horizontal strip, e.g. `9437` / `94B7`)

```
; map cell (full byte is stamp id — no lo7 mask)
di  = 31D4 + (822C + col_i) * 100 + (8230 + row_mod)
id  = [es:di]                      ; zero-extend → DS:2D82
SI  = 207A + id * 24               ; mul bx,18h
[5DE4] = SI ; [5DE6] = DS
call sub_83                        ; 2B9A
```

#### `sub_83` @ `2B9A` — full 2×6 stamp → offscreen

```
cx = 6
si = [5DE4]                        ; stamp source
es = ds
dl = 50h                           ; 80 = 40 cells * 2 bytes/row
for each of 6 rows (bx = 0,2,...,10; row = bx>>1):
  di_row = (row + [810C]) * 50h
  di     = di_row + ([810E] << 1) + [206C]
  movsw ; movsw                    ; 2 cells (char,attr)(char,attr)
```

#### `sub_84` @ `2BCD` — half-height (2 rows)

Same body as `sub_83` with `cx=2` (used on vertical strip edges, e.g. call @ `975D`).

#### Col-39 half-width (inline, not `sub_83`)

Path around `9522` / `95C0`: for each map row strip, sets `810C = row*6+2`, loads one stamp, then **6×** single-word write to offscreen at `col<<1` (one cell wide) while advancing stamp SI by 4 per row.

#### Present offscreen → visible page

- **`sub_81` @ `2B71`**: `rep movsw` of `cx=0FA0h` words from `[206C:206E]` → page dest (`2BF2/2BF4`). Tall buffer (2× 40×25 words), not a single page.
- **`sub_82` @ `2B8C`**: INT10 AH=05 set active display page from `5DDC` bit0.

#### Viewport geometry (unchanged, now cited)

```
tile_x / tile_y live in DS:822C / DS:8230
(world → tile still: (world - 2880|2400) / 288)

screen_col = (i << 1) + 1          ; 1,3,...,37 for i=0..18
screen_row = row_arg * 6 + 2       ; 2,8,14,20
map_byte   = [31D4 + (tile_x+i)*100 + (tile_y+row_arg)]
```

| Item | Value |
|------|--------|
| MAP stride | **100** (`mul bx,64h`) on X |
| Stamp id | **full MAP byte** |
| Bank | BA 96 + BB 96 = **192** × 24 B @ `207A` |
| Viewport | **19** full stamps + col-39 half; row phase **2**, col phase **1** |
| Draw target | Offscreen @ `206C`, then page blit |

Stamp examples (chars only; attrs recolored live):

| Id | Pattern | Role |
|----|---------|------|
| 0, 12 | all `DE` | floor |
| 10, 14 | all `B1` | green wall |
| 11 | all `83` | red brick |
| 130+ | mixed DE/B1/B0 | edge / transition (BB range) |

#### Not terrain: `2F65` / `sub_90`

`mov al,data_123[di]` @ `2F65` walks MAP with stride 100 for **collision / walkability** (`cmp al,0` / `cmp al,9`), not drawing.

#### ICON0 MAP load → `31D4` — **RLE confirmed** (`ICON0.LST` ~`1209`…`1305`)

On-disk `L*.MAP` is **run-length compressed** (file often padded to a fixed size; only the leading stream is consumed).

```
prev = 0
while dest_count < map_size:          ; LA → 3840 = 38×100
  b = getbyte(stream)                 ; sub_253
  if b <= 7Fh:
    emit b; prev = b                  ; literal
  else:
    n = b & 7Fh
    emit (n - 1) extra copies of prev ; total run length = n
```

Verified: RLE(`LA.MAP`) **==** live `MAPRT.BIN` (3840/3840).  
Sourcer loop uses `F4--` then `for F2=2..n` writes of previous = same `(n−1)` extras after the literal already stored.

Raw `LA.MAP` vs runtime was only ~15% — that was the missing RLE, not a “bake table.”

### File-mode parity — **100%** (2026-07-20)

```
bake(BA.DAT) + RLE(LA.MAP) + blit @ cam(0,0)
  == STAMPS.BIN + MAPRT.BIN blit
  == dummy/expected_b800_parity.bin
```

Sprites/HUD still overwrite terrain on live B800; terrain cells match.

```bash
python3 games/icon-quest-for-the-ring/decode_map.py LA --camera 0,0
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

1. **Dummy draw path in ASM** — done (terrain parity).
2. **Authentic load staging** — done (v5 multi-frame intro).
3. **File bake + MAP RLE** — done (v6; no STAMPS/MAPRT required).
4. **Then** host PNG / disk tools that reuse the same blit rules; sprites next.

**Parity result (mem dump g0013 + B800):** 19 full stamps + col-39 half-stamp; **100% terrain** bytes; remaining diffs = player sprite (bottom, cols 7–9).

### Dummy loader stages (v6) vs ICON.EXE

User-visible intro order:

1. **Title** — gold ring / “icon” / Macrocom (e.g. `/tmp/start.png`)  
2. **Animation** — after ESC (e.g. `/tmp/animation.png`)  
3. Then menus/story/OVL/assets → overworld  

| Stage | ASM label | Authentic bit |
|-------|-----------|----------------|
| TITLE | `stage_title` | mode 00→01; blit `TITLE.BIN` (2000 B B800 page); wait ESC |
| video | `icon_mode_01` | INT10 00/01 + AX=1102 fonts only (CRTC 09=81h alone crushes playfield in DOSBox — omitted) |
| ANI | `stage_ani` | mode 00→01; blit `ANI.BIN`; wait ESC |
| OVL0 | `stage_ovl0` | FCB `ICON0.OVL`, 243×128 sequential read (discard) |
| ASSETS | `stage_assets` | BA/BB **count+payload bake** + LA.MAP **RLE** (+ LA/MA.DAT) **or** STAMPS+MAPRT |
| OVL1 | `stage_ovl1` | FCB `ICON1.OVL`, 399×128 read (discard) |
| PLAY | `stage_play` | terrain blit (ICON1 rules) |

Capture `TITLE.BIN` / `ANI.BIN` with **Ctrl+F10** while each screen is fully painted (mode-set auto-dumps are often mid-frame).

## Level MAP (`L*.MAP`) — **RLE + index confirmed**

| File | On-disk size | Format |
|------|--------------|--------|
| LA…LG | 3712–4736 | **RLE stream** (often padded); expand to stamp-id grid |

On-disk bytes frequently have high bit set (~RLE markers). Expanded LA: values **0..90**, stride **100**, width **38** (`38×100=3800`, buffer **3840**).

### RLE (ICON0 → `DS:31D4`)

See above (“ICON0 MAP load”). File size ≠ expanded size; decoder stops at target map size (or EOF).

### Index formula (ICON1, many call sites)

```
addr = DS:31D4 + tile_x * 100 + tile_y
tile_id = mem[addr]          ; full byte → stamp @ 207A + tile_id*24
; collision probes treat id <= 9 specially (sub_90 @ 2F65)
```

Viewport: **19** stamp columns + col-39 half; vertical step **6** text rows; camera **(0,0)** after correct RLE (old `(7,75)` was a raw-MAP workaround).

### Decode tool

```bash
python3 games/icon-quest-for-the-ring/decode_map.py LA --camera 0,0
# → map_preview/LA_decoded.png, LA_viewport.png, BA_stamps_2x6.png
```

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

Length-prefixed ASCII labels interleaved with binary frames.  
SP is a superset/variant of DR (more creatures/FX; snakes, dwarves, ghosts, …).

### On-disk frame shape (*strong*)

```
len:u8, name[len]          ; ASCII label
w:u8, h:u8                 ; width × height in text cells
mask[w*h]                  ; per-cell color / material index
                           ;   0x10 = transparent (skip blit)
                           ;   other = palette slot (fed through DS:2906)
rest…                      ; optional char plane (often starts 01h)
                           ;   packed CP437 chars for non-transparent cells
```

Examples: `man front` / `skeleton` = **6×12**; `health bar` = **6×21** (mask-only colors `01/07/09`, rest = `00`); `Bat 0` = **6×4**.

Hero pose set in DR: `man front`, `man * weapon`, `man * swing`, plus **`skeleton`** (death pose, same 6×12 footprint).

### CP437 hero glyphs (from DR char plane)

Man / skeleton streams include block art and a **triangle** cell:

| Byte | CP437 (IBM) | Role |
|------|-------------|------|
| `0x1E` | ▲ up triangle | present in banks; possible flash/UI |
| `0x1F` | ▼ down triangle | **in man + skeleton char streams** (e.g. after `12 de`) |
| `0x2A` | `*` | torso-ish accents |
| `0xDE` / `0x7C` | ▐ / `\|` | fill / limbs |
| `0x02`… | face / detail | with attrs from mask remap |

Live play notes: wound flash is a **triangle glyph** that recolors (**yellow** when hurt, **red** when critical). Direction (up vs down) is easy to misread in CGA text — treat as “triangle,” check `1E`/`1F` at runtime. Death: hero swaps to **`skeleton`** (yellowish bone colors in mask: `0x0E` yellow-ish slots dominate vs man’s multicolor mask) **before** the death banner.

### Damage / death UX (player report + ICON1 strings)

| State | Visual | Notes |
|-------|--------|--------|
| Hurt | Triangle → **yellow** | attr recolor via sprite pipeline, not terrain |
| Critical | Triangle → **red** | same glyph, hotter palette |
| Dead | Body → **yellow-ish skeleton** frame | label `skeleton` in DR/SP |
| Then | Centered death text | see below |

### Live capture (to-play → level A, 2026-07-20)

Automation reached overworld (`STARTUP-PROMPTS.md` + Esc×2).  
Dump `ICON_g0011_m01_…0005.bin` vs terrain parity: **1988/2000** match; **7 cells** = hero:

| Pos (col,row) | char | attr | Notes |
|---------------|------|------|--------|
| (8,20) | `02` | `70` | body |
| (8,21) | `2A` | `F1` | `*` |
| (8,22) | `09` | `F4` | |
| (8,23) | `12` | `7F` | |
| (7,24) | `DE` | `75` | floor tint |
| **(8,24)** | **`1F`** | **`85`** | **▼ triangle (healthy)** |
| (9,24) | `DE` | `57` | floor tint |

Confirmed: wound flash glyph is **CP437 `1Fh`** (down triangle), not `1Eh`.

| State | Triangle attr | Notes |
|-------|---------------|--------|
| Healthy | **`85h`** | blink + fg (spawn dump g0011) |
| **Hurt (bat hit)** | **`8Eh`** | **blink + yellow fg** — player: yellow triangle after bat; also seen mid-wander |
| Critical | `8Ch`? | *hypothesis* blink + light red (same high bit as 85/8E) |

Automation often **misses** the hurt frame if F10 is not fired during the flash (flash is brief).

### Level A sword (player + data)

| Fact | Detail |
|------|--------|
| Spawn | `LA.DAT` / `LA.ADV` **`3 3`** (map tiles) |
| Sword | **6 steps south** of hero (walk **Down** ×6) |
| Pick up | **`P`** (F1: “P · Pick up object”); joystick btn #2 |
| Art | DR **`sword`** 6×3 sprite (`0x60` cells), not MAP stamp |
| Drop | **`D`** |

`LA.DAT` object pairs after count `4` still *hypothesis* (type/params); ground path is south-of-spawn + **P**.

### Level A ground objects (live 2026-07-20 + DR)

| Visual | DR label | Notes |
|--------|----------|--------|
| Sword on ground → equip | `sword` | ~6 south of spawn; **P** on tile; then cyan blade in hand |
| Yellow/brown coin pile | **`gold`** | At least **two** piles on level A open floor (lower + upper-right) |
| Red/blue `+` | Bat frames (MA `Bat`) | Mobile; not a pickup |

Live RE notebook: `ICON/LIVE-RE-SESSION.md`. Pickup only succeeds **on tile** (else arm-reach, no state change; map/offscr dumps can stay byte-identical).

Death / fail strings in **ICON1.OVL** (dispatch on `DS:2C16` cause id):

| Cause id (*partial*) | Message |
|----------------------|---------|
| … | `"… Killed You!"` (killer name prefix) |
| 4 | `You Were Hit By Lightning!` |
| 5 | `You Weren't Ready For The Icon!` |
| 6 | `You Materialized In A Wall!` |
| 7 | `The Black Knight killed you` + `when your Magic Sword broke!` |
| default | `You Died!` |
| other | `You Drowned!`, `You Have Been Burnt To A Cinder!`, … |

Pattern: show sprite state → `sub_103` / `sub_269` paint message → `sub_298(-1,-1)` wait/ack.

### Runtime color remap (ICON1)

- **`DS:2906`**: table of **4 bytes × slot** (written at init ~`A00B` and by setter ~`2088`).  
- **`sub_89` @ `2D8B`**: sprite cell blit — mask indices → `2906[idx*4 + (5DDC&3)]`; **`0x10` = transparent**; blends with underlying offscreen char at `2BF2/2BF4`.  
- Wound yellow/red is almost certainly **remapping mask slots** (or swapping the 4-entry row for the hero), not redrawing BA terrain.  
- Death pose = **frame select** `skeleton` rather than only recoloring `man front`.

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


## Sourcer 8.01 listings

Multi-pass listings for `ICON.EXE` / `ICON0..2.OVL` live in `sourcer-out/`
(regenerate: `cd SOURCER && ./run_sr.sh all`).

Batch requirements: **CRLF** `.DEF` with **`Go`**, run as `sr ICON.DEF -n -x` under DOSBox.
Help: `sr -? 2>&1 > loki.txt` → `LOKI.TXT`.

### Sourcer landmarks (quick index)

| Module | Offset | Symbol / meaning |
|--------|--------|------------------|
| ICON1 | `2B9A` | **`sub_83`** — 2×6 stamp → offscreen |
| ICON1 | `2BCD` | **`sub_84`** — 2-row half-height stamp |
| ICON1 | `2B71` | **`sub_81`** — offscreen → page (`rep movsw` 0FA0h) |
| ICON1 | `2B8C` | **`sub_82`** — set display page |
| ICON1 | `9437`… | Horizontal strip: map index → `207A+id*24` → `sub_83` |
| ICON1 | `9522`… | Edge / half-width column fill |
| ICON1 | `2F65` | MAP walk probe (not draw) |
| ICON0 | `0B54`… | Stamp bank bake into `207A` |
| ICON / ICON1 | `206C`, `31D4` | Offscreen ptr; MAP base |

ICON.LST / ICON1.LST labels: **`DS:206C`**, **`DS:31D4`** (`data_123` / `data_179`).
