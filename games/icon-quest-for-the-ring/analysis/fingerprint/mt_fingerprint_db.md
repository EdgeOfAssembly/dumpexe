# Pascal MT+ 3.1.1 → ICON fingerprint database
**Compiler:** Pascal MT+86 for MS-DOS 3.1.1 (Digital Research, 12-03-84)
**Matches:** 60
**Jump table slots @ 0090h:** 23

## Images

| Image | Size | Entry CALL target | Seg table (code/data/stack/extra paras) |
|-------|------|-------------------|----------------------------------------|
| `ICON.EXE` | 35328 | 25899 | 0xc80/0x8b0/0x90/0x0 |
| `ICON0.OVL` | 31744 | 19565 | 0xc80/0x8b0/0x90/0x0 |
| `ICON1.OVL` | 51712 | 41093 | 0xc80/0x8b0/0x90/0x0 |
| `ICON2.OVL` | 24064 | 14011 | 0xc80/0x8b0/0x90/0x0 |

## High-confidence matches (sample)

| Image | File off | IP/img off | Role | Pattern | Conf |
|-------|----------|------------|------|---------|------|
| `ICON.EXE` | 0x0200 | 0x0000 | pascal_mt_startup_call | `entry_e8` | 0.99 |
| `ICON.EXE` | 0x0203 | 0x0003 | pascal_mt_segment_table | `entry_segtable` | 0.99 |
| `ICON.EXE` | 0x02EE | 0x00EE | rtl_error_string | `str_pascal_mt_error` | 0.99 |
| `ICON.EXE` | 0x17D4 | 0x15D4 | game_version_string | `str_icon_11` | 0.99 |
| `ICON.EXE` | 0x1ED0 | 0x1CD0 | overlay_chain_name | `str_icon0` | 0.99 |
| `ICON.EXE` | 0x1EED | 0x1CED | overlay_chain_name | `str_icon0` | 0.99 |
| `ICON0.OVL` | 0x0200 | 0x0000 | pascal_mt_startup_call | `entry_e8` | 0.99 |
| `ICON0.OVL` | 0x0203 | 0x0003 | pascal_mt_segment_table | `entry_segtable` | 0.99 |
| `ICON0.OVL` | 0x02F4 | 0x00F4 | rtl_error_string | `str_pascal_mt_error` | 0.99 |
| `ICON0.OVL` | 0x20E6 | 0x1EE6 | overlay_chain_name | `str_icon1` | 0.99 |
| `ICON0.OVL` | 0x2103 | 0x1F03 | overlay_chain_name | `str_icon1` | 0.99 |
| `ICON1.OVL` | 0x0200 | 0x0000 | pascal_mt_startup_call | `entry_e8` | 0.99 |
| `ICON1.OVL` | 0x0203 | 0x0003 | pascal_mt_segment_table | `entry_segtable` | 0.99 |
| `ICON1.OVL` | 0x0306 | 0x0106 | rtl_error_string | `str_pascal_mt_error` | 0.99 |
| `ICON1.OVL` | 0x2812 | 0x2612 | overlay_chain_name | `str_icon2` | 0.99 |
| `ICON1.OVL` | 0x282F | 0x262F | overlay_chain_name | `str_icon0` | 0.99 |
| `ICON1.OVL` | 0x284C | 0x264C | overlay_chain_name | `str_icon2` | 0.99 |
| `ICON1.OVL` | 0x293C | 0x273C | overlay_chain_name | `str_icon2` | 0.99 |
| `ICON1.OVL` | 0x2959 | 0x2759 | overlay_chain_name | `str_icon2` | 0.99 |
| `ICON2.OVL` | 0x0200 | 0x0000 | pascal_mt_startup_call | `entry_e8` | 0.99 |
| `ICON2.OVL` | 0x0203 | 0x0003 | pascal_mt_segment_table | `entry_segtable` | 0.99 |
| `ICON2.OVL` | 0x02DC | 0x00DC | rtl_error_string | `str_pascal_mt_error` | 0.99 |
| `ICON2.OVL` | 0x0AC6 | 0x08C6 | game_version_string | `str_icon_11` | 0.99 |
| `ICON.EXE` | 0x1ACC | 0x18CC | cga_requirement | `str_cga` | 0.95 |
| `ICON.EXE` | 0x67AF | 0x65AF | startup_read_data_size_paras | `inipc_cs_word_5` | 0.95 |
| `ICON.EXE` | 0x67BA | 0x65BA | startup_read_extra_size_paras | `inipc_cs_word_9` | 0.95 |
| `ICON0.OVL` | 0x4EF1 | 0x4CF1 | startup_read_data_size_paras | `inipc_cs_word_5` | 0.95 |
| `ICON0.OVL` | 0x4EFC | 0x4CFC | startup_read_extra_size_paras | `inipc_cs_word_9` | 0.95 |
| `ICON1.OVL` | 0xA309 | 0xA109 | startup_read_data_size_paras | `inipc_cs_word_5` | 0.95 |
| `ICON1.OVL` | 0xA314 | 0xA114 | startup_read_extra_size_paras | `inipc_cs_word_9` | 0.95 |
| `ICON2.OVL` | 0x393F | 0x373F | startup_read_data_size_paras | `inipc_cs_word_5` | 0.95 |
| `ICON2.OVL` | 0x394A | 0x374A | startup_read_extra_size_paras | `inipc_cs_word_9` | 0.95 |
| `ICON.EXE` | 0x672D | 0x652D | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON.EXE` | 0x6732 | 0x6532 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON.EXE` | 0x6737 | 0x6537 | startup_add_stack_size | `inipc_add_cs_7` | 0.9 |
| `ICON.EXE` | 0x674B | 0x654B | rtl_oom | `str_out_of_memory` | 0.9 |
| `ICON.EXE` | 0x676A | 0x656A | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON.EXE` | 0x6787 | 0x6587 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON0.OVL` | 0x4E6F | 0x4C6F | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON0.OVL` | 0x4E74 | 0x4C74 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON0.OVL` | 0x4E79 | 0x4C79 | startup_add_stack_size | `inipc_add_cs_7` | 0.9 |
| `ICON0.OVL` | 0x4E8D | 0x4C8D | rtl_oom | `str_out_of_memory` | 0.9 |
| `ICON0.OVL` | 0x4EAC | 0x4CAC | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON0.OVL` | 0x4EC9 | 0x4CC9 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON1.OVL` | 0xA287 | 0xA087 | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON1.OVL` | 0xA28C | 0xA08C | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON1.OVL` | 0xA291 | 0xA091 | startup_add_stack_size | `inipc_add_cs_7` | 0.9 |
| `ICON1.OVL` | 0xA2A5 | 0xA0A5 | rtl_oom | `str_out_of_memory` | 0.9 |
| `ICON1.OVL` | 0xA2C4 | 0xA0C4 | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON1.OVL` | 0xA2E1 | 0xA0E1 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON2.OVL` | 0x38BD | 0x36BD | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON2.OVL` | 0x38C2 | 0x36C2 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |
| `ICON2.OVL` | 0x38C7 | 0x36C7 | startup_add_stack_size | `inipc_add_cs_7` | 0.9 |
| `ICON2.OVL` | 0x38DB | 0x36DB | rtl_oom | `str_out_of_memory` | 0.9 |
| `ICON2.OVL` | 0x38FA | 0x36FA | startup_add_code_size | `inipc_add_cs_3` | 0.9 |
| `ICON2.OVL` | 0x3917 | 0x3717 | startup_add_data_size | `inipc_add_cs_5` | 0.9 |

## Jump table @ ICON.EXE IP 0090h

| Slot | Table IP | Target IP | File off (target) | Prologue / note |
|------|----------|-----------|-------------------|-----------------|
| 0 | 0090 | 1885 | 0x1A85 | calls_further `e8374b` |
| 1 | 0093 | 00D5 | 0x02D5 | pascal_near_proc_frame `558bec5581ec` |
| 2 | 0096 | 011A | 0x031A | pascal_near_proc_frame `558bec5581ec` |
| 3 | 0099 | 0149 | 0x0349 | pascal_near_proc_frame `558bec5581ec` |
| 4 | 009C | 016F | 0x036F | pascal_near_proc_frame `558bec5581ec` |
| 5 | 009F | 01AD | 0x03AD | pascal_near_proc_frame `558bec5581ec` |
| 6 | 00A2 | 01D2 | 0x03D2 | pascal_near_proc_frame `558bec5581ec` |
| 7 | 00A5 | 02B8 | 0x04B8 | pascal_near_proc_frame `558bec5581ec` |
| 8 | 00A8 | 0892 | 0x0A92 | pascal_near_proc_frame `558bec5581ec` |
| 9 | 00AB | 0332 | 0x0532 |  `558bc4ff76fe` |
| 10 | 00AE | 04BB | 0x06BB |  `558bc4ff76fe` |
| 11 | 00B1 | 0B34 | 0x0D34 | pascal_near_proc_frame `558bec5581ec` |
| 12 | 00B4 | 0BAF | 0x0DAF | pascal_near_proc_frame `558bec5581ec` |
| 13 | 00B7 | 0C05 | 0x0E05 | pascal_near_proc_frame `558bec5581ec` |
| 14 | 00BA | 0F89 | 0x1189 | pascal_near_proc_frame `558bec5581ec` |
| 15 | 00BD | 1064 | 0x1264 | pascal_near_proc_frame `558bec5581ec` |
| 16 | 00C0 | 125B | 0x145B | pascal_near_proc_frame `558bec5581ec` |
| 17 | 00C3 | 140D | 0x160D | pascal_near_proc_frame `558bec5581ec` |
| 18 | 00C6 | 1467 | 0x1667 | pascal_near_proc_frame `558bec5581ec` |
| 19 | 00C9 | 165C | 0x185C | pascal_near_proc_frame `558bec5581ec` |
| 20 | 00CC | 16DA | 0x18DA | pascal_near_proc_frame `558bec5581ec` |
| 21 | 00CF | 16FA | 0x18FA | pascal_near_proc_frame `558bec5581ec` |
| 22 | 00D2 | 17B4 | 0x19B4 | pascal_near_proc_frame `558bec5581ec` |

## Spot-check vs MT+ sources

1. **INIPC.I86** uses `CS:WORD PTR [3],[5],[7],[9]` — matched via `2E A1 0x 00` / `2E 03 06 0x 00` in ICON images.
2. **Pascal MT+ Error** string present in all four MZ (PASLIB/runtime).
3. **icon0.ovl / icon1.ovl** names as Pascal CALL-inline strings in chain loaders.
4. Entry `E8 xx xx` then segment table — same as documented MT+ EXE layout.
