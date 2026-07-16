#!/usr/bin/env python3
"""Decode DOSBox debugtrace B800 screen dumps to PNG.

Expects dumps from screen_dump (char,attr little-endian words):
  ICON_gNNNN_mMM_bB8000_s07D0_NNNN.bin  (+ optional .meta)

Usage:
  python3 decode_screen_dump.py
  python3 decode_screen_dump.py ICON/screen_dumps/ICON_g0011_m01_bB8000_s07D0_0006.bin
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image

HERE = Path(__file__).resolve().parent
DEFAULT_DUMP_DIR = HERE / "ICON" / "screen_dumps"
OUT = HERE / "map_preview"

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


def _g(*rows: int) -> np.ndarray:
    return np.array(rows, dtype=np.uint8)


GLYPHS: dict[int, np.ndarray] = {
    0x00: _g(0, 0, 0, 0, 0, 0, 0, 0),
    0x20: _g(0, 0, 0, 0, 0, 0, 0, 0),
    0xDB: _g(*([0xFF] * 8)),
    0xFE: _g(*([0xFF] * 8)),
    0xDC: _g(0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF),
    0xDF: _g(0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0),
    0xDD: _g(*([0xF0] * 8)),
    0xDE: _g(*([0x0F] * 8)),
    0xB0: _g(0x44, 0x11, 0x44, 0x11, 0x44, 0x11, 0x44, 0x11),
    0xB1: _g(0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55),
    0xB2: _g(0xEE, 0xBB, 0xEE, 0xBB, 0xEE, 0xBB, 0xEE, 0xBB),
    # ICON brick-ish (common in BA.DAT / live terrain)
    0x83: _g(0xFF, 0xEE, 0xFF, 0x77, 0xFF, 0xEE, 0xFF, 0x77),
    0x01: _g(0x18, 0x3C, 0x7E, 0xFF, 0xFF, 0x7E, 0x3C, 0x18),
    0x02: _g(0x18, 0x3C, 0x7E, 0xFF, 0x7E, 0x3C, 0x18, 0x00),
    0x09: _g(0x00, 0x18, 0x3C, 0x7E, 0x18, 0x18, 0x18, 0x00),
    0x12: _g(0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00),
    0x1F: _g(0x00, 0x00, 0x00, 0xFF, 0x7E, 0x3C, 0x18, 0x00),
    0x2A: _g(0x00, 0x24, 0x18, 0x7E, 0x18, 0x24, 0x00, 0x00),
    0xB3: _g(*([0x18] * 8)),
    0xC4: _g(0, 0, 0, 0xFF, 0xFF, 0, 0, 0),
    0xDA: _g(0, 0, 0, 0x1F, 0x18, 0x18, 0x18, 0x18),
    0xBF: _g(0, 0, 0, 0xF8, 0x18, 0x18, 0x18, 0x18),
    0xC0: _g(0x18, 0x18, 0x18, 0x18, 0x1F, 0, 0, 0),
    0xD9: _g(0x18, 0x18, 0x18, 0x18, 0xF8, 0, 0, 0),
    0xC3: _g(0x18, 0x18, 0x18, 0x1F, 0x18, 0x18, 0x18, 0x18),
    0xB4: _g(0x18, 0x18, 0x18, 0xF8, 0x18, 0x18, 0x18, 0x18),
    0xC2: _g(0, 0, 0, 0xFF, 0x18, 0x18, 0x18, 0x18),
    0xC1: _g(0x18, 0x18, 0x18, 0x18, 0xFF, 0, 0, 0),
    0xC5: _g(0x18, 0x18, 0x18, 0xFF, 0x18, 0x18, 0x18, 0x18),
}


def glyph(ch: int) -> np.ndarray:
    ch &= 0xFF
    if ch in GLYPHS:
        return GLYPHS[ch]
    if 0x20 < ch < 0x7F:
        return _g(0x00, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00)
    return _g(0x7E, 0x42, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x00)


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


def parse_meta(path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    if not path.is_file():
        return meta
    for line in path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            meta[k.strip()] = v.strip()
    return meta


def render_b800(data: bytes, cols: int, rows: int, scale: int = 4) -> np.ndarray:
    need = cols * rows * 2
    if len(data) < need:
        raise ValueError(f"dump too small: {len(data)} < {need}")
    img = np.zeros((rows * 8, cols * 8, 3), np.uint8)
    for y in range(rows):
        for x in range(cols):
            i = (y * cols + x) * 2
            ch, attr = data[i], data[i + 1]  # native B800: char, attr
            img[y * 8 : (y + 1) * 8, x * 8 : (x + 1) * 8] = cell_rgb(ch, attr)
    if scale != 1:
        img = np.repeat(np.repeat(img, scale, 0), scale, 1)
    return img


def decode_one(bin_path: Path, out_dir: Path, scale: int = 4) -> Path:
    data = bin_path.read_bytes()
    meta = parse_meta(bin_path.with_suffix(".meta"))
    cols = int(meta.get("cols", "40" if len(data) <= 2000 else "80"))
    rows = int(meta.get("rows", "25"))
    # infer if meta missing
    if cols * rows * 2 != len(data):
        if len(data) == 2000:
            cols, rows = 40, 25
        elif len(data) == 4000:
            cols, rows = 80, 25
        elif len(data) == 0x4000:
            # full 16k — still render first page as 40x25 or 80x25 guess
            cols, rows = 40, 25
    img = render_b800(data, cols, rows, scale=scale)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"b800_{bin_path.stem}.png"
    Image.fromarray(img).save(out)
    reason = meta.get("reason", "?")
    mode = meta.get("mode", "?")
    print(f"{bin_path.name}: mode={mode} {cols}x{rows} reason={reason} → {out.name}")
    return out


def main(argv: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    if len(argv) > 1:
        paths = [Path(a) for a in argv[1:]]
    else:
        paths = sorted(DEFAULT_DUMP_DIR.glob("*.bin"))
    if not paths:
        print("no .bin dumps found", file=sys.stderr)
        return 1
    for p in paths:
        if not p.is_file():
            print(f"missing {p}", file=sys.stderr)
            continue
        decode_one(p, OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
