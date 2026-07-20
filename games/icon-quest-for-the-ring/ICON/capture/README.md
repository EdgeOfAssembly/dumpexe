# Gameplay capture filmstrip

## Staging screenshots (real pixels)

Configured in `dosbox-auto.conf`:

```ini
[capture]
capture_dir = capture
default_image_capture_formats = rendered,upscaled
```

| Key | Staging meaning |
|-----|-----------------|
| **Ctrl+F5** | Default screenshot action (formats above) |
| **Alt+F5** | Rendered image (post-scaler / what you usually see) |

`auto_icon.sh` fires both and copies new PNGs into:

```text
capture/filmstrip_YYYYMMDD_HHMMSS/
  0001_boot_….png
  0002_overworld_….png
  0003_south_1_….png
  …
```

Env:

```bash
PNG_SHOT=1          # default on — Staging F5 shots
SHOT_HOST=1         # optional host window grab (import/maim/scrot)
CAPTURE_DIR=…       # default: ICON/capture
```

## Fork B800 dumps (RE, not pictures)

| Key | Output |
|-----|--------|
| **Ctrl+F10** | `screen_dumps/*.bin` raw text page |
| **Ctrl+F11** | `mem_dumps/*` stamps/map/offscreen |

Use PNGs to **see** play; use B800 to **measure** attrs (e.g. triangle `8Eh` yellow hurt).

## After a run

```bash
ls -lt capture/filmstrip_*/ | head
# open filmstrip in order and tune script steps
```
