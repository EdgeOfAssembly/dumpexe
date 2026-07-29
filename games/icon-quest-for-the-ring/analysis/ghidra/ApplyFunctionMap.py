#@category ICON
# Apply analysis/function_map.json labels into the current program.
# Headless: analyzeHeadless <proj> <name> -process ICON.EXE -postScript ApplyFunctionMap.py <path-to-function_map.json>

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
import json
import os

args = getScriptArgs()
json_path = args[0] if args else None
if not json_path:
    # default relative to project
    json_path = "/tmp/dumpexe/games/icon-quest-for-the-ring/analysis/function_map.json"

with open(json_path, "r") as f:
    data = json.load(f)

prog = currentProgram
name = prog.getName()
# map image names
image_aliases = {
    "ICON.EXE": ["ICON.EXE", "ICON"],
    "ICON0.OVL": ["ICON0.OVL", "ICON0"],
    "ICON1.OVL": ["ICON1.OVL", "ICON1"],
    "ICON2.OVL": ["ICON2.OVL", "ICON2"],
}

def matches_image(img):
    aliases = image_aliases.get(img, [img])
    for a in aliases:
        if name.upper().startswith(a.upper().split(".")[0]):
            return True
    return name.upper() == img.upper()

fm = prog.getFunctionManager()
st = prog.getSymbolTable()
listing = prog.getListing()
mem = prog.getMemory()
base = mem.getMinAddress()
# DOS MZ: image often loaded at segment; file offset = header(0x200) + IP for many tools
# Ghidra real-mode often uses file bytes at address space starting at 0 or load image.
# Prefer image_offset when present; else file_offset - 0x200 if >= 0x200.

applied = 0
skipped = 0
for p in data.get("procedures", []):
    img = p.get("image")
    if not matches_image(img):
        continue
    gname = p.get("ghidra_name")
    if not gname:
        continue
    fo = p.get("file_offset")
    if fo is None:
        skipped += 1
        continue
    # Try file-bytes address first (common for dumpexe-aligned projects)
    addr = base.add(fo)
    if not mem.contains(addr):
        # try load image offset
        io = p.get("image_offset")
        if io is not None:
            addr = base.add(io)
        elif fo >= 0x200:
            addr = base.add(fo - 0x200)
    if not mem.contains(addr):
        skipped += 1
        continue
    try:
        createLabel(addr, gname, True, SourceType.USER_DEFINED)
        applied += 1
    except Exception as e:
        print("label fail %s @ %s: %s" % (gname, addr, e))
        skipped += 1

print("ApplyFunctionMap: program=%s applied=%d skipped=%d" % (name, applied, skipped))
