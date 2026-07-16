#!/usr/bin/env python3
"""Decode ICON L*.MAP + BA.DAT to a PNG (mode 01h text-mode stamps).

Confirmed from ICON1 disassembly + DOSBox mode 01h:

  BA.DAT  2304 B = 96 stamps × 24 B
  Stamp   2×6 text cells, row-major
  On-disk pair order that matches screenshot art: attr, char
  Draw    6 rows × 2× movsw into an 80-byte-stride text buffer (B800-like)

  MAP cell index (ICON1):  base + x * 100 + y
  LA.MAP  3840 B ≈ 38×100 usable + short tail (often 0x1A padding)

  Tile id = map_byte & 0x7F  (max observed 90; fits 96 stamps)
  Bit 7   = flag (collision / priority) — not required for graphics

Usage:
  python3 decode_map.py              # LA + BA → map_preview/LA_decoded.png
  python3 decode_map.py LB BB
"""

from __future__ import annotations

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
    if c in (0x00, 0x20, 0xFF):
        return np.zeros(8, np.uint8)
    if c == 0x01:
        return np.array([0x18, 0x3C, 0x7E, 0xFF, 0xFF, 0x7E, 0x3C, 0x18], np.uint8)
    return np.array([0x7E, 0x7E, 0x7E, 0x7E, 0x7E, 0x7E, 0x7E, 0x00], np.uint8)


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


def load_stamps(ba: bytes) -> list[np.ndarray]:
    """96 stamps of 2×6 cells; on-disk attr,char pairs."""
    assert len(ba) == 2304, len(ba)
    stamps: list[np.ndarray] = []
    for i in range(0, 2304, 24):
        chunk = ba[i : i + 24]
        img = np.zeros((48, 16, 3), np.uint8)
        for row in range(6):
            for col in range(2):
                off = (row * 2 + col) * 2
                attr, ch = chunk[off], chunk[off + 1]
                img[row * 8 : (row + 1) * 8, col * 8 : (col + 1) * 8] = cell_rgb(ch, attr)
        stamps.append(img)
    return stamps


def map_dims(n: int, stride: int = STRIDE) -> tuple[int, int, int]:
    """Return (width_x, height_y, used_bytes)."""
    used = (n // stride) * stride
    width = used // stride
    return width, stride, used


def render_map(mp: bytes, stamps: list[np.ndarray], lo7: bool = True) -> np.ndarray:
    w, h, used = map_dims(len(mp))
    img = np.zeros((h * 48, w * 16, 3), np.uint8)
    nstamp = len(stamps)
    for x in range(w):
        for y in range(h):
            b = mp[x * STRIDE + y]
            idx = (b & 0x7F) if lo7 else b
            if idx >= nstamp:
                tile = np.full((48, 16, 3), [255, 0, 255], np.uint8)
            else:
                tile = stamps[idx]
            img[y * 48 : (y + 1) * 48, x * 16 : (x + 1) * 16] = tile
    return img


def stamp_sheet(stamps: list[np.ndarray], cols: int = 16) -> np.ndarray:
    rows = (len(stamps) + cols - 1) // cols
    gap = 2
    tw, th = 16 + gap, 48 + gap
    sheet = np.full((rows * th, cols * tw, 3), 40, np.uint8)
    for i, s in enumerate(stamps):
        r, c = divmod(i, cols)
        sheet[r * th : r * th + 48, c * tw : c * tw + 16] = s
    return sheet


def main(argv: list[str]) -> int:
    level = argv[1] if len(argv) > 1 else "LA"
    bank = argv[2] if len(argv) > 2 else "BA"
    map_path = ICON / f"{level}.MAP"
    ba_path = ICON / f"{bank}.DAT"
    if not map_path.is_file() or not ba_path.is_file():
        print(f"missing {map_path} or {ba_path}", file=sys.stderr)
        return 1

    mp = map_path.read_bytes()
    ba = ba_path.read_bytes()
    stamps = load_stamps(ba)
    w, h, used = map_dims(len(mp))
    print(f"{map_path.name}: {len(mp)} B → {w}×{h} stamps (stride {STRIDE}, used {used})")
    print(f"{ba_path.name}: {len(stamps)} stamps × 2×6 cells")

    level_img = render_map(mp, stamps, lo7=True)
    out_level = OUT / f"{level}_decoded.png"
    Image.fromarray(level_img).save(out_level)
    print(f"wrote {out_level} ({level_img.shape[1]}×{level_img.shape[0]})")

    sheet = stamp_sheet(stamps)
    out_sheet = OUT / f"{bank}_stamps_2x6.png"
    Image.fromarray(sheet).save(out_sheet)
    print(f"wrote {out_sheet}")

    # Viewport-ish strip: 19×5 stamps (matches ICON1 loop 0..0x12 cols)
    vw, vh = min(19, w), min(5, h)
    # try a few origins; pick densest solid region near start
    best = None
    solid = np.frombuffer(mp[:used], dtype=np.uint8).reshape(w, h)
    for ox in range(0, max(1, w - vw + 1), 2):
        for oy in range(0, max(1, h - vh + 1), 2):
            block = solid[ox : ox + vw, oy : oy + vh]
            score = int(np.sum((block & 0x7F) > 9))
            if best is None or score > best[0]:
                best = (score, ox, oy)
    assert best is not None
    _, ox, oy = best
    view = level_img[oy * 48 : (oy + vh) * 48, ox * 16 : (ox + vw) * 16]
    # scale ×2 for readability
    view2 = np.repeat(np.repeat(view, 2, 0), 2, 1)
    out_view = OUT / f"{level}_viewport.png"
    Image.fromarray(view2).save(out_view)
    print(f"wrote {out_view} origin stamp=({ox},{oy}) score={best[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
