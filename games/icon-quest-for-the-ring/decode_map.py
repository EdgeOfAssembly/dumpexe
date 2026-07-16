#!/usr/bin/env python3
"""Decode ICON L*.MAP + BA.DAT[/BB.DAT] to a PNG (mode 01h text stamps).

Confirmed from ICON1 + live B800 dumps (2026-07-17):

  Stamp bank   BA.DAT (and BB.DAT when loaded) at runtime DS:207A
  Stamp size   24 bytes = 2×6 text cells
  On-disk pair attr, char  (swap to char,attr for B800)
  MAP index    DS:31D4 + tile_x * 100 + tile_y
  MAP byte     full value is stamp index (0..180; 96+ is in BB if concatenated)
  Viewport     19 stamps wide at cols 1,3,...,37; strip row = n*6+2
  Scroll       off-screen buffer; vertical steps of 6 text rows (one stamp)

  Live B800 is char,attr. Engine may recolor attributes; characters match bank.

Usage:
  python3 decode_map.py              # LA + BA+BB → map_preview/LA_decoded.png
  python3 decode_map.py LB
  python3 decode_map.py LA --camera 7,75
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
from PIL import Image

HERE = Path(__file__).resolve().parent
ICON = HERE / "ICON"
OUT = HERE / "map_preview"
OUT.mkdir(exist_ok=True)

CGA = np.array(
    [
        [0, 0, 0],
        [0, 0, 170],
        [0, 170, 0],
        [0, 170, 170],
        [170, 0, 0],
        [170, 0, 170],
        [170, 85, 0],
        [170, 170, 170],
        [85, 85, 85],
        [85, 85, 255],
        [85, 255, 85],
        [85, 255, 255],
        [255, 85, 85],
        [255, 85, 255],
        [255, 255, 85],
        [255, 255, 255],
    ],
    dtype=np.uint8,
)

STRIDE = 100  # map index = x * STRIDE + y


def glyph(ch: int) -> np.ndarray:
    c = ch & 0xFF
    if c in (0xDB, 0xFE):
        return np.full(8, 0xFF, np.uint8)
    if c == 0xDC:
        return np.array([0, 0, 0, 0, 255, 255, 255, 255], np.uint8)
    if c == 0xDF:
        return np.array([255, 255, 255, 255, 0, 0, 0, 0], np.uint8)
    if c == 0xDD:
        return np.full(8, 0xF0, np.uint8)
    if c == 0xDE:
        return np.full(8, 0x0F, np.uint8)
    if c == 0xB0:
        return np.array([0x44, 0x11, 0x44, 0x11, 0x44, 0x11, 0x44, 0x11], np.uint8)
    if c == 0xB1:
        return np.array([0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55], np.uint8)
    if c == 0xB2:
        return np.array([0xEE, 0xBB, 0xEE, 0xBB, 0xEE, 0xBB, 0xEE, 0xBB], np.uint8)
    if c == 0x83:
        return np.array([0xFF, 0xEE, 0xFF, 0x77, 0xFF, 0xEE, 0xFF, 0x77], np.uint8)
    if c in (0x00, 0x20, 0xFF):
        return np.zeros(8, np.uint8)
    return np.array([0x7E, 0x42, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x00], np.uint8)


def cell_rgb(ch: int, attr: int) -> np.ndarray:
    fg = CGA[attr & 0x0F]
    bg = CGA[(attr >> 4) & 0x07]
    g = glyph(ch)
    img = np.zeros((8, 8, 3), np.uint8)
    for r in range(8):
        bits = int(g[r])
        for c in range(8):
            img[r, c] = fg if (bits >> (7 - c)) & 1 else bg
    return img


def load_bank() -> bytes:
    ba = (ICON / "BA.DAT").read_bytes()
    bb_path = ICON / "BB.DAT"
    if bb_path.is_file():
        return ba + bb_path.read_bytes()
    return ba


def stamp_cells(bank: bytes, idx: int) -> list[tuple[int, int]]:
    """Return 12 (ch, attr) cells in B800 order, row-major 2×6."""
    n = len(bank) // 24
    if idx < 0 or idx >= n:
        idx = 0
    raw = bank[idx * 24 : (idx + 1) * 24]
    cells = []
    for i in range(12):
        attr, ch = raw[i * 2], raw[i * 2 + 1]  # on-disk attr,char
        cells.append((ch, attr))
    return cells


def map_dims(n: int, stride: int = STRIDE) -> tuple[int, int, int]:
    used = (n // stride) * stride
    width = used // stride
    return width, stride, used


def render_full_map(mp: bytes, bank: bytes, scale: int = 1) -> np.ndarray:
    """Full level: each MAP byte → 2×6 stamp (16×48 px at scale 1)."""
    w, h, used = map_dims(len(mp))
    nstamp = len(bank) // 24
    img = np.zeros((h * 48, w * 16, 3), np.uint8)
    for x in range(w):
        for y in range(h):
            idx = int(mp[x * STRIDE + y]) % max(nstamp, 1)
            cells = stamp_cells(bank, idx)
            for ci, (ch, attr) in enumerate(cells):
                row, col = divmod(ci, 2)
                img[y * 48 + row * 8 : y * 48 + (row + 1) * 8,
                    x * 16 + col * 8 : x * 16 + (col + 1) * 8] = cell_rgb(ch, attr)
    if scale != 1:
        img = np.repeat(np.repeat(img, scale, 0), scale, 1)
    return img


def render_viewport(
    mp: bytes,
    bank: bytes,
    cam_x: int,
    cam_y: int,
    *,
    vw: int = 19,
    vh: int = 4,
    cph: int = 1,
    rph: int = 2,
    scale: int = 3,
) -> np.ndarray:
    """40×25 screen reconstruction (ICON1 strip geometry)."""
    nstamp = len(bank) // 24
    canvas = np.zeros((25 * 8, 40 * 8, 3), np.uint8)
    for sr in range(vh):
        for sc in range(vw):
            mx, my = cam_x + sc, cam_y + sr
            i = mx * STRIDE + my
            if i < 0 or i >= len(mp):
                continue
            idx = int(mp[i]) % max(nstamp, 1)
            cells = stamp_cells(bank, idx)
            col0, row0 = cph + sc * 2, rph + sr * 6
            if col0 + 2 > 40 or row0 + 6 > 25:
                continue
            for ci, (ch, attr) in enumerate(cells):
                r, c = divmod(ci, 2)
                canvas[
                    (row0 + r) * 8 : (row0 + r + 1) * 8,
                    (col0 + c) * 8 : (col0 + c + 1) * 8,
                ] = cell_rgb(ch, attr)
    if scale != 1:
        canvas = np.repeat(np.repeat(canvas, scale, 0), scale, 1)
    return canvas


def stamp_sheet(bank: bytes, cols: int = 16) -> np.ndarray:
    n = len(bank) // 24
    rows = (n + cols - 1) // cols
    gap = 2
    tw, th = 16 + gap, 48 + gap
    sheet = np.full((rows * th, cols * tw, 3), 40, np.uint8)
    for i in range(n):
        r, c = divmod(i, cols)
        cells = stamp_cells(bank, i)
        for ci, (ch, attr) in enumerate(cells):
            rr, cc = divmod(ci, 2)
            sheet[
                r * th + rr * 8 : r * th + (rr + 1) * 8,
                c * tw + cc * 8 : c * tw + (cc + 1) * 8,
            ] = cell_rgb(ch, attr)
    return sheet


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("level", nargs="?", default="LA", help="level letter, e.g. LA")
    ap.add_argument(
        "--camera",
        default=None,
        help="viewport camera as X,Y (map stamp coords), e.g. 7,75",
    )
    args = ap.parse_args(argv[1:])

    level = args.level.upper().replace(".MAP", "")
    if len(level) == 1:
        level = "L" + level
    map_path = ICON / f"{level}.MAP"
    if not map_path.is_file():
        print(f"missing {map_path}", file=sys.stderr)
        return 1

    mp = map_path.read_bytes()
    bank = load_bank()
    w, h, used = map_dims(len(mp))
    nstamp = len(bank) // 24
    print(f"{map_path.name}: {len(mp)} B → {w}×{h} (stride {STRIDE}, used {used})")
    print(f"stamp bank: {nstamp} × 2×6 cells ({len(bank)} B)")

    full = render_full_map(mp, bank, scale=1)
    out_full = OUT / f"{level}_decoded.png"
    Image.fromarray(full).save(out_full)
    print(f"wrote {out_full} ({full.shape[1]}×{full.shape[0]})")

    sheet = stamp_sheet(bank)
    out_sheet = OUT / "BA_BB_stamps_2x6.png"
    Image.fromarray(sheet).save(out_sheet)
    print(f"wrote {out_sheet}")

    if args.camera:
        cx, cy = (int(x) for x in args.camera.split(","))
    else:
        # Default: middle-ish; user can pass --camera after RE lock
        cx, cy = max(0, w // 4), max(0, h // 4)
    view = render_viewport(mp, bank, cx, cy)
    out_view = OUT / f"{level}_viewport_{cx}_{cy}.png"
    Image.fromarray(view).save(out_view)
    print(f"wrote {out_view} camera=({cx},{cy}) cols=1+2k rows=2+6n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
