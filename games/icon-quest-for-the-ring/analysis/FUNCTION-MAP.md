# ICON function / procedure map

**Generated:** 2026-07-29T21:36:58Z from `function_map.json` (source: fingerprint DB).

## Summary

| Metric | Value |
|--------|-------|
| Procedures annotated | 83 |
| Jump-table slots @ IP 0090h | 23 |
| Fingerprint matches | 60 |
| Tier A / B / C | 60 / 21 / 2 |

## Jump table @ ICON.EXE IP 0090h (Pascal procedure vectors)

| Slot | IP | Target | File off | Ghidra label | Tier | Role |
|------|----|--------|----------|--------------|------|------|
| 0 | 0090 | 1885 | 0x1A85 | `jt_00_calls_further` | B | calls_further |
| 1 | 0093 | 00D5 | 0x02D5 | `jt_01_pascal_near` | B | pascal_near_proc_frame |
| 2 | 0096 | 011A | 0x031A | `jt_02_pascal_near` | B | pascal_near_proc_frame |
| 3 | 0099 | 0149 | 0x0349 | `jt_03_pascal_near` | B | pascal_near_proc_frame |
| 4 | 009C | 016F | 0x036F | `jt_04_pascal_near` | B | pascal_near_proc_frame |
| 5 | 009F | 01AD | 0x03AD | `jt_05_pascal_near` | B | pascal_near_proc_frame |
| 6 | 00A2 | 01D2 | 0x03D2 | `jt_06_pascal_near` | B | pascal_near_proc_frame |
| 7 | 00A5 | 02B8 | 0x04B8 | `jt_07_pascal_near` | B | pascal_near_proc_frame |
| 8 | 00A8 | 0892 | 0x0A92 | `jt_08_pascal_near` | B | pascal_near_proc_frame |
| 9 | 00AB | 0332 | 0x0532 | `jt_09_game_or_rtl` | C | game_or_rtl_proc |
| 10 | 00AE | 04BB | 0x06BB | `jt_10_game_or_rtl` | C | game_or_rtl_proc |
| 11 | 00B1 | 0B34 | 0x0D34 | `jt_11_pascal_near` | B | pascal_near_proc_frame |
| 12 | 00B4 | 0BAF | 0x0DAF | `jt_12_pascal_near` | B | pascal_near_proc_frame |
| 13 | 00B7 | 0C05 | 0x0E05 | `jt_13_pascal_near` | B | pascal_near_proc_frame |
| 14 | 00BA | 0F89 | 0x1189 | `jt_14_pascal_near` | B | pascal_near_proc_frame |
| 15 | 00BD | 1064 | 0x1264 | `jt_15_pascal_near` | B | pascal_near_proc_frame |
| 16 | 00C0 | 125B | 0x145B | `jt_16_pascal_near` | B | pascal_near_proc_frame |
| 17 | 00C3 | 140D | 0x160D | `jt_17_pascal_near` | B | pascal_near_proc_frame |
| 18 | 00C6 | 1467 | 0x1667 | `jt_18_pascal_near` | B | pascal_near_proc_frame |
| 19 | 00C9 | 165C | 0x185C | `jt_19_pascal_near` | B | pascal_near_proc_frame |
| 20 | 00CC | 16DA | 0x18DA | `jt_20_pascal_near` | B | pascal_near_proc_frame |
| 21 | 00CF | 16FA | 0x18FA | `jt_21_pascal_near` | B | pascal_near_proc_frame |
| 22 | 00D2 | 17B4 | 0x19B4 | `jt_22_pascal_near` | B | pascal_near_proc_frame |

## Major RTL / load / I/O sites (fingerprint, tier A preferred)

| Image | File off | Ghidra label | Tier | Role | Evidence |
|-------|----------|--------------|------|------|----------|
| `ICON.EXE` | 0x0203 | `pascal_mt_segment_table__0203` | A | pascal_mt_segment_table | words 0C80,08B0,0090,0000 after CALL |
| `ICON.EXE` | 0x0200 | `pascal_mt_startup_call__0200` | A | pascal_mt_startup_call | E8 rel16 → IP 652Bh |
| `ICON.EXE` | 0x67AF | `startup_read_data_size_paras__67AF` | A | startup_read_data_size_paras | 2ea10500 |
| `ICON.EXE` | 0x67BA | `startup_read_extra_size_paras__67BA` | A | startup_read_extra_size_paras | 2ea10900 |
| `ICON.EXE` | 0x672D | `startup_add_code_size__672D` | A | startup_add_code_size | 2e03060300 |
| `ICON.EXE` | 0x676A | `startup_add_code_size__676A` | A | startup_add_code_size | 2e03060300 |
| `ICON.EXE` | 0x6732 | `startup_add_data_size__6732` | A | startup_add_data_size | 2e03060500 |
| `ICON.EXE` | 0x6787 | `startup_add_data_size__6787` | A | startup_add_data_size | 2e03060500 |
| `ICON.EXE` | 0x6737 | `startup_add_stack_size__6737` | A | startup_add_stack_size | 2e03060700 |
| `ICON.EXE` | 0x6760 | `dos_print_string__6760` | A | dos_print_string | b409cd21 |
| `ICON.EXE` | 0x02EE | `rtl_error_string__02EE` | A | rtl_error_string | Pascal MT+ Error |
| `ICON.EXE` | 0x17D4 | `game_version_string__17D4` | A | game_version_string | ICON 1.1 |
| `ICON.EXE` | 0x1ED0 | `overlay_chain_name__1ED0` | A | overlay_chain_name | icon0.ovl |
| `ICON.EXE` | 0x1EED | `overlay_chain_name__1EED` | A | overlay_chain_name | icon0.ovl |
| `ICON.EXE` | 0x1ACC | `cga_requirement__1ACC` | A | cga_requirement | Color Graphics |
| `ICON.EXE` | 0x674B | `rtl_oom__674B` | A | rtl_oom | OUT OF MEMORY |
| `ICON0.OVL` | 0x0203 | `pascal_mt_segment_table__0203` | A | pascal_mt_segment_table | words 0C80,08B0,0090,0000 after CALL |
| `ICON0.OVL` | 0x0200 | `pascal_mt_startup_call__0200` | A | pascal_mt_startup_call | E8 rel16 → IP 4C6Dh |
| `ICON0.OVL` | 0x4EF1 | `startup_read_data_size_paras__4EF1` | A | startup_read_data_size_paras | 2ea10500 |
| `ICON0.OVL` | 0x4EFC | `startup_read_extra_size_paras__4EFC` | A | startup_read_extra_size_paras | 2ea10900 |
| `ICON0.OVL` | 0x4E6F | `startup_add_code_size__4E6F` | A | startup_add_code_size | 2e03060300 |
| `ICON0.OVL` | 0x4EAC | `startup_add_code_size__4EAC` | A | startup_add_code_size | 2e03060300 |
| `ICON0.OVL` | 0x4E74 | `startup_add_data_size__4E74` | A | startup_add_data_size | 2e03060500 |
| `ICON0.OVL` | 0x4EC9 | `startup_add_data_size__4EC9` | A | startup_add_data_size | 2e03060500 |
| `ICON0.OVL` | 0x4E79 | `startup_add_stack_size__4E79` | A | startup_add_stack_size | 2e03060700 |
| `ICON0.OVL` | 0x4EA2 | `dos_print_string__4EA2` | A | dos_print_string | b409cd21 |
| `ICON0.OVL` | 0x02F4 | `rtl_error_string__02F4` | A | rtl_error_string | Pascal MT+ Error |
| `ICON0.OVL` | 0x20E6 | `overlay_chain_name__20E6` | A | overlay_chain_name | icon1.ovl |
| `ICON0.OVL` | 0x2103 | `overlay_chain_name__2103` | A | overlay_chain_name | icon1.ovl |
| `ICON0.OVL` | 0x4E8D | `rtl_oom__4E8D` | A | rtl_oom | OUT OF MEMORY |
| `ICON1.OVL` | 0x0203 | `pascal_mt_segment_table__0203` | A | pascal_mt_segment_table | words 0C80,08B0,0090,0000 after CALL |
| `ICON1.OVL` | 0x0200 | `pascal_mt_startup_call__0200` | A | pascal_mt_startup_call | E8 rel16 → IP A085h |
| `ICON1.OVL` | 0xA309 | `startup_read_data_size_paras__A309` | A | startup_read_data_size_paras | 2ea10500 |
| `ICON1.OVL` | 0xA314 | `startup_read_extra_size_paras__A314` | A | startup_read_extra_size_paras | 2ea10900 |
| `ICON1.OVL` | 0xA287 | `startup_add_code_size__A287` | A | startup_add_code_size | 2e03060300 |
| `ICON1.OVL` | 0xA2C4 | `startup_add_code_size__A2C4` | A | startup_add_code_size | 2e03060300 |
| `ICON1.OVL` | 0xA28C | `startup_add_data_size__A28C` | A | startup_add_data_size | 2e03060500 |
| `ICON1.OVL` | 0xA2E1 | `startup_add_data_size__A2E1` | A | startup_add_data_size | 2e03060500 |
| `ICON1.OVL` | 0xA291 | `startup_add_stack_size__A291` | A | startup_add_stack_size | 2e03060700 |
| `ICON1.OVL` | 0xA2BA | `dos_print_string__A2BA` | A | dos_print_string | b409cd21 |
| `ICON1.OVL` | 0x0306 | `rtl_error_string__0306` | A | rtl_error_string | Pascal MT+ Error |
| `ICON1.OVL` | 0x282F | `overlay_chain_name__282F` | A | overlay_chain_name | icon0.ovl |
| `ICON1.OVL` | 0x2812 | `overlay_chain_name__2812` | A | overlay_chain_name | icon2.ovl |
| `ICON1.OVL` | 0x284C | `overlay_chain_name__284C` | A | overlay_chain_name | icon2.ovl |
| `ICON1.OVL` | 0x293C | `overlay_chain_name__293C` | A | overlay_chain_name | icon2.ovl |
| `ICON1.OVL` | 0x2959 | `overlay_chain_name__2959` | A | overlay_chain_name | icon2.ovl |
| `ICON1.OVL` | 0xA2A5 | `rtl_oom__A2A5` | A | rtl_oom | OUT OF MEMORY |
| `ICON2.OVL` | 0x0203 | `pascal_mt_segment_table__0203` | A | pascal_mt_segment_table | words 0C80,08B0,0090,0000 after CALL |
| `ICON2.OVL` | 0x0200 | `pascal_mt_startup_call__0200` | A | pascal_mt_startup_call | E8 rel16 → IP 36BBh |
| `ICON2.OVL` | 0x393F | `startup_read_data_size_paras__393F` | A | startup_read_data_size_paras | 2ea10500 |
| `ICON2.OVL` | 0x394A | `startup_read_extra_size_paras__394A` | A | startup_read_extra_size_paras | 2ea10900 |
| `ICON2.OVL` | 0x38BD | `startup_add_code_size__38BD` | A | startup_add_code_size | 2e03060300 |
| `ICON2.OVL` | 0x38FA | `startup_add_code_size__38FA` | A | startup_add_code_size | 2e03060300 |
| `ICON2.OVL` | 0x38C2 | `startup_add_data_size__38C2` | A | startup_add_data_size | 2e03060500 |
| `ICON2.OVL` | 0x3917 | `startup_add_data_size__3917` | A | startup_add_data_size | 2e03060500 |
| `ICON2.OVL` | 0x38C7 | `startup_add_stack_size__38C7` | A | startup_add_stack_size | 2e03060700 |
| `ICON2.OVL` | 0x38F0 | `dos_print_string__38F0` | A | dos_print_string | b409cd21 |
| `ICON2.OVL` | 0x02DC | `rtl_error_string__02DC` | A | rtl_error_string | Pascal MT+ Error |
| `ICON2.OVL` | 0x0AC6 | `game_version_string__0AC6` | A | game_version_string | ICON 1.1 |
| `ICON2.OVL` | 0x38DB | `rtl_oom__38DB` | A | rtl_oom | OUT OF MEMORY |

## Chain model

```
ICON.EXE → icon0.ovl → icon1.ovl → icon2.ovl
All share Pascal MT+ entry CALL + segment table at CS+3.
Startup target IP (ICON.EXE): 652Bh (file 0x672B).
```

## Ghidra labels

Machine-readable: `analysis/function_map.json` field `procedures[].ghidra_name`.
Import project: `analysis/ghidra/icon_project.gpr`.
Apply via headless script or manual rename at file offsets listed above.

## Citations

- dumpexe `--strings` → `analysis/dumpexe/*/strings.txt`
- r2 → `analysis/r2/*-static.txt`
- fingerprint → `analysis/fingerprint/mt_fingerprint_db.json`
- function map → `analysis/function_map.json`
- MT+ sources → `/tmp/Pascal MT-86 3.1.1 for MSDOS/b/INIPC.I86`, `OVLMGRPC.I86`
