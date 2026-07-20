; icon_dummy.asm - ICON.EXE-like staged loader + terrain play (UASM)
;
; Goal: authentic *loading sequence* corresponding to real ICON.EXE, with
; the draw path we already proved - not a full Pascal MT+ reimplementation.
;
; Real chain (live FCB log):
;   ICON.EXE
;     -> mode 00/01 title + intro animation (ESC skip)
;     -> ICON0.OVL  (block-read)
;     -> BA.DAT, LA.MAP, LA.DAT, MA.DAT
;     -> ICON1.OVL  (block-read)
;     -> overworld play (mode 01h terrain)
;
; Our stages (same order / same FCB names; OVL bytes read+discarded):
;   STAGE_TITLE   loop TITLES.BIN frames (or TITLE.BIN x1) until ESC
;   STAGE_ANI     loop ANIS.BIN frames (or ANI.BIN x1) until ESC
;   STAGE_OVL0    FCB open+block-read ICON0.OVL (discard records)
;   STAGE_ASSETS  BA/BB/LA.MAP/LA.DAT/MA.DAT or STAMPS+MAPRT
;   STAGE_OVL1    FCB open+block-read ICON1.OVL (discard)
;   STAGE_PLAY    clear B800, map->stamp blit, arrows/R/ESC
;
; Capture (no timestamps):
;   make clean-dumps
;   ICON.EXE: spam Ctrl+F10 while ring animates, then quit
;   make install-title-frames   -> TITLES.BIN
;   make clean-dumps
;   ICON.EXE: ESC title, spam Ctrl+F10 on particles, quit
;   make install-ani-frames     -> ANIS.BIN
;
; Build:  uasm -bin -Fo icon_dummy.com icon_dummy.asm
; Run:    from ICON/ directory
;
.8086
.model tiny
.code
org     100h

start:
        jmp     main

; ---------------------------------------------------------------------------
; Constants (ICON1 terrain) — Sourcer ICON1.LST landmarks:
;   MAP @ DS:31D4 (data_123), stamps @ DS:207A, offscreen @ DS:206C
;   sub_83 @ 2B9A = 2x6 movsw (cx=6, stride 50h) via 5DE4 / 810C / 810E
;   sub_84 @ 2BCD = 2-row half-height; sub_81 @ 2B71 = offscreen->page
;   Dummy draws straight to B800 (parity with live dumps; skip offscreen).
; ---------------------------------------------------------------------------
MAP_STRIDE      equ     100             ; mul bx,64h in strip index
STAMP_BYTES     equ     24              ; mul bx,18h
STAMP_COUNT     equ     192             ; BA||BB bank at 207A
VIEW_W          equ     19              ; full stamps (cols 1..37)
VIEW_H          equ     4               ; stamp rows (screen rows 2,8,14,20)
COL0            equ     1               ; 810E phase: (i<<1)+1
ROW0            equ     2               ; 810C phase: row*6+2
; File-mode after bake+RLE matches runtime tables → same cam origin.
CAM_X0_FILE     equ     0
CAM_Y0_FILE     equ     0
CAM_X0_RT       equ     0
CAM_Y0_RT       equ     0

BA_SIZE         equ     2304
BB_SIZE         equ     2304
BANK_SIZE       equ     BA_SIZE + BB_SIZE
MAP_SIZE        equ     3840
SCR_SIZE        equ     40*25*2         ; 2000 = mode 01 page
MAX_FRAMES      equ     8               ; max title/ani frames in RAM
FRAME_DELAY     equ     2               ; BIOS timer ticks (~110ms) per frame
LADAT_MAX       equ     128             ; LA.DAT is 96 on disk
MADAT_MAX       equ     512             ; MA.DAT is 502
; ICON0 31744/128 = 248; log used 243. ICON1 51712/128 = 404; log used 399.
OVL0_RECS       equ     243
OVL1_RECS       equ     399

; ---------------------------------------------------------------------------
; Messages (shown in mode 03 between stages or on error/exit)
; ---------------------------------------------------------------------------
msg_banner      db      'ICON dummy loader v8 - terrain + hero + objects (RE 2026-07-20)',0Dh,0Ah
                db      'TITLE/ANI Esc; PLAY: arrows cam, 1-4 hero, P pick, R reset, Esc quit',0Dh,0Ah
                db      '1=ok 2=hurt(8Eh) 3=crit 4=dead; P=sword (LA.DAT tile 3,10); gold HUD',0Dh,0Ah,'$'
msg_stage_t     db      '[stage] TITLE (TITLES.BIN multi-frame loop)',0Dh,0Ah,'$'
msg_stage_a     db      '[stage] ANI (ANIS.BIN multi-frame loop)',0Dh,0Ah,'$'
msg_stage_0     db      '[stage] ICON0.OVL FCB block-read',0Dh,0Ah,'$'
msg_stage_as    db      '[stage] BA/BB bake + LA.MAP RLE + LA/MA.DAT',0Dh,0Ah,'$'
msg_stage_rt    db      '[stage] assets: STAMPS.BIN + MAPRT.BIN (parity)',0Dh,0Ah,'$'
msg_stage_1     db      '[stage] ICON1.OVL FCB block-read',0Dh,0Ah,'$'
msg_stage_p     db      '[stage] PLAY (terrain + objects + hero; P/1-4)',0Dh,0Ah,'$'
msg_dead        db      '  You Died!  (4=skeleton; 1=stand)  $'
msg_got_sword   db      'Got sword! $'
msg_got_gold    db      'Gold+1 $'
msg_no_title    db      '(no TITLES.BIN/TITLE.BIN - blank title)',0Dh,0Ah,'$'
msg_no_ani      db      '(no ANIS.BIN/ANI.BIN - blank ani)',0Dh,0Ah,'$'
msg_no_ovl0     db      'FCB open ICON0.OVL failed (continuing).',0Dh,0Ah,'$'
msg_no_ovl1     db      'FCB open ICON1.OVL failed (continuing).',0Dh,0Ah,'$'
msg_no_ba       db      'FCB open BA.DAT failed.',0Dh,0Ah,'$'
msg_no_map      db      'FCB open LA.MAP failed.',0Dh,0Ah,'$'
msg_bye         db      0Dh,0Ah,'ICON dummy exit. last stage play; mode was: $'
msg_bye_rt      db      'parity tables',0Dh,0Ah,'$'
msg_bye_file    db      'file BA bake + MAP RLE',0Dh,0Ah,'$'

; ASCIZ paths for handle I/O (multi-frame files)
path_titles     db      'TITLES.BIN',0
path_title1     db      'TITLE.BIN',0
path_anis       db      'ANIS.BIN',0
path_ani1       db      'ANI.BIN',0

; ---------------------------------------------------------------------------
; FCBs - 8.3 space-padded (UASM: split db lines)
; ---------------------------------------------------------------------------
fcb_ovl0:
        db 0, 'ICON0   ', 'OVL', 25 dup (0)
fcb_ovl1:
        db 0, 'ICON1   ', 'OVL', 25 dup (0)
fcb_stamps:
        db 0, 'STAMPS  ', 'BIN', 25 dup (0)
fcb_maprt:
        db 0, 'MAPRT   ', 'BIN', 25 dup (0)
fcb_ba:
        db 0, 'BA      ', 'DAT', 25 dup (0)
fcb_bb:
        db 0, 'BB      ', 'DAT', 25 dup (0)
fcb_map:
        db 0, 'LA      ', 'MAP', 25 dup (0)
fcb_ladat:
        db 0, 'LA      ', 'DAT', 25 dup (0)
fcb_madat:
        db 0, 'MA      ', 'DAT', 25 dup (0)

; ---------------------------------------------------------------------------
; State
; ---------------------------------------------------------------------------
cam_x   dw      CAM_X0_FILE
cam_y   dw      CAM_Y0_FILE
mode_rt db      0                       ; 1 = parity STAMPS+MAPRT
nframes_t db    0                       ; title frame count
nframes_a db    0                       ; ani frame count
frame_i   db    0                       ; playback index
; hero_state: 0=ok 1=hurt 2=critical 3=dead (live ICON g0011 capture)
hero_state db   0
; Live overworld hero (B800 diffs vs terrain parity @ cam 0,0):
;   col8 rows20-24: 02/70 2A/F1 09/F4 12/7F 1F/85  + feet DE recolor
; Triangle = CP437 1Fh (▼) attr 85h healthy; wound recolors that cell.
HERO_COL        equ     8
HERO_ROW0       equ     20
TRI_CH          equ     1Fh             ; confirmed live dump g0011
ATTR_OK         equ     85h             ; healthy triangle (blink + magenta-ish)
ATTR_HURT       equ     8Eh             ; bat hit: blink + yellow fg (player report + 8Eh dumps)
ATTR_CRIT       equ     8Ch             ; blink + light red (guess, same blink bit)
ATTR_DEAD       equ     0Eh             ; skeleton yellow-ish (no blink)
;
; --- Level A object RE (Sourcer ICON0/ICON1 + LA.DAT, 2026-07-20) ---
; LA.DAT header: spawn 3 3; origin 2880 2400; line5 gold_quota=4 (not object count)
; 11 fixed-type slots (indices 91..101); slot 91 = sword at tile (3,10)
; Gold piles: ICON1 mass-init type DS:2BEA; counter DS:2BEC; quota DS:5A24
; Pickup: key P (AX=50h after AND 5Fh fold) -> sub_17 @1549 (AABB) -> sub_135
; Entity rec DS:5A9C stride 6 (x,y,type); side DS:2C1A stride 6
; B800 dumps miss sword/gold sprites (page flip / sprite layer) — ground art
; below is VISUAL_APPROX from live rendered shots, not B800 cell proof.
SWORD_TILE_X    equ     3
SWORD_TILE_Y    equ     10
SPAWN_TILE_X    equ     3
SPAWN_TILE_Y    equ     3
GOLD_QUOTA_LA   equ     4               ; LA.DAT line 5 (basic); ADV=8
; Live mem dumps 2026-07-20 after sword pick:
;   DS:8228 equip FFFF -> 0019h; side ent91 x=0C y=3C type=19 -> x=FFFE
;   ents idx91 type 19 -> FFFF; gold type DS:2BEA=0017h; hero_idx=5
SWORD_TYPE_ID   equ     19h
GOLD_TYPE_ID    equ     17h
sword_alive     db      1               ; 1 = still on ground
sword_equipped  db      0               ; 1 = after successful P (equip type 19h)
gold_alive0     db      1               ; decorative pile (visual)
gold_alive1     db      1
gold_count      db      0               ; mirrors DS:2BEC
gold_quota      db      GOLD_QUOTA_LA
steps_south     db      0               ; cam downs since reset (proxy for tile y)

; ---------------------------------------------------------------------------
main:
        push    cs
        pop     ds
        push    cs
        pop     es

        mov     ax, 0003h               ; 80-col for banners
        int     10h
        mov     dx, offset msg_banner
        mov     ah, 09h
        int     21h

; ===========================================================================
; STAGE_TITLE - multi-frame loop (TITLES.BIN) or single TITLE.BIN
; ===========================================================================
stage_title:
        mov     dx, offset msg_stage_t
        mov     ah, 09h
        int     21h

        mov     byte ptr nframes_t, 0
        mov     dx, offset path_titles
        mov     bx, offset scr_title
        call    load_frames
        mov     byte ptr nframes_t, al
        cmp     al, 0
        jne     title_play

        ; fallback single TITLE.BIN
        mov     dx, offset path_title1
        mov     bx, offset scr_title
        call    load_frames
        mov     byte ptr nframes_t, al
        cmp     al, 0
        jne     title_play

        mov     dx, offset msg_no_title
        mov     ah, 09h
        int     21h
        mov     di, offset scr_title
        mov     cx, SCR_SIZE
        xor     al, al
        rep     stosb
        mov     byte ptr nframes_t, 1

title_play:
        call    icon_mode_01
        mov     al, nframes_t
        mov     bx, offset scr_title
        call    play_frames             ; until ESC

; ===========================================================================
; STAGE_ANI - multi-frame loop (ANIS.BIN) or single ANI.BIN
; ===========================================================================
stage_ani:
        mov     ax, 0003h
        int     10h
        mov     dx, offset msg_stage_a
        mov     ah, 09h
        int     21h

        mov     byte ptr nframes_a, 0
        mov     dx, offset path_anis
        mov     bx, offset scr_ani
        call    load_frames
        mov     byte ptr nframes_a, al
        cmp     al, 0
        jne     ani_play

        mov     dx, offset path_ani1
        mov     bx, offset scr_ani
        call    load_frames
        mov     byte ptr nframes_a, al
        cmp     al, 0
        jne     ani_play

        mov     dx, offset msg_no_ani
        mov     ah, 09h
        int     21h
        mov     di, offset scr_ani
        mov     cx, SCR_SIZE
        xor     al, al
        rep     stosb
        mov     byte ptr nframes_a, 1

ani_play:
        call    icon_mode_01
        mov     al, nframes_a
        mov     bx, offset scr_ani
        call    play_frames

; ===========================================================================
; STAGE_OVL0 - ICON0.OVL block-read (same rec count as live log)
; ===========================================================================
stage_ovl0:
        mov     ax, 0003h
        int     10h
        mov     dx, offset msg_stage_0
        mov     ah, 09h
        int     21h

        mov     dx, offset fcb_ovl0
        call    fcb_open
        jc      ovl0_fail
        mov     dx, offset fcb_ovl0
        mov     cx, OVL0_RECS
        call    fcb_read_discard        ; authentic traffic, no 31KB resident
        jmp     stage_assets
ovl0_fail:
        mov     dx, offset msg_no_ovl0
        mov     ah, 09h
        int     21h

; ===========================================================================
; STAGE_ASSETS - BA/BB/MAP or parity dumps + LA.DAT + MA.DAT
; ===========================================================================
stage_assets:
        mov     byte ptr mode_rt, 0

        ; Prefer runtime parity tables if present
        mov     dx, offset fcb_stamps
        call    fcb_open
        jc      assets_files
        mov     dx, offset fcb_stamps
        mov     bx, offset bank_buf
        mov     cx, BANK_SIZE / 128
        call    fcb_read_all
        mov     dx, offset fcb_maprt
        call    fcb_open
        jc      assets_files
        mov     dx, offset fcb_maprt
        mov     bx, offset map_buf
        mov     cx, MAP_SIZE / 128
        call    fcb_read_all
        mov     byte ptr mode_rt, 1
        mov     word ptr cam_x, CAM_X0_RT
        mov     word ptr cam_y, CAM_Y0_RT
        mov     dx, offset msg_stage_rt
        mov     ah, 09h
        int     21h
        jmp     assets_ladat

assets_files:
        mov     dx, offset msg_stage_as
        mov     ah, 09h
        int     21h

        mov     dx, offset fcb_ba
        call    fcb_open
        jc      err_ba
        mov     dx, offset fcb_ba
        mov     bx, offset bank_buf
        mov     cx, BA_SIZE / 128
        call    fcb_read_all
        ; ICON0 sub_32: count=getbyte, then count stamps of 12 words
        mov     si, offset bank_buf
        mov     di, offset bank_buf
        mov     bx, BA_SIZE
        call    bake_stamp_file

        mov     dx, offset fcb_bb
        call    fcb_open
        jc      bb_zero
        mov     dx, offset fcb_bb
        mov     bx, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE / 128
        call    fcb_read_all
        mov     si, offset bank_buf + BA_SIZE
        mov     di, offset bank_buf + BA_SIZE
        mov     bx, BB_SIZE
        call    bake_stamp_file
        jmp     load_map
bb_zero:
        mov     di, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE
        xor     al, al
        rep     stosb
load_map:
        mov     dx, offset fcb_map
        call    fcb_open
        jc      err_map
        ; RLE stream into map_raw, expand to map_buf (ICON0 ~1209)
        mov     dx, offset fcb_map
        mov     bx, offset map_raw
        mov     cx, MAP_SIZE / 128
        call    fcb_read_all
        call    decode_map_rle
        mov     word ptr cam_x, CAM_X0_FILE
        mov     word ptr cam_y, CAM_Y0_FILE

assets_ladat:
        ; LA.DAT (small) - load if present
        mov     dx, offset fcb_ladat
        call    fcb_open
        jc      assets_madat
        mov     dx, offset fcb_ladat
        mov     bx, offset ladat_buf
        mov     cx, 1                   ; one 128 B record covers 96 B file
        call    fcb_read_all
assets_madat:
        mov     dx, offset fcb_madat
        call    fcb_open
        jc      stage_ovl1
        mov     dx, offset fcb_madat
        mov     bx, offset madat_buf
        mov     cx, 4                   ; 512 B
        call    fcb_read_all
        jmp     stage_ovl1

err_ba:
        mov     dx, offset msg_no_ba
        mov     ah, 09h
        int     21h
        jmp     exit_err
err_map:
        mov     dx, offset msg_no_map
        mov     ah, 09h
        int     21h
        jmp     exit_err

; ===========================================================================
; STAGE_OVL1 - ICON1.OVL then PLAY
; ===========================================================================
stage_ovl1:
        mov     dx, offset msg_stage_1
        mov     ah, 09h
        int     21h

        mov     dx, offset fcb_ovl1
        call    fcb_open
        jc      ovl1_fail
        mov     dx, offset fcb_ovl1
        mov     cx, OVL1_RECS
        call    fcb_read_discard
        jmp     stage_play
ovl1_fail:
        mov     dx, offset msg_no_ovl1
        mov     ah, 09h
        int     21h

; ===========================================================================
; STAGE_PLAY - ICON1 terrain (proven path)
; ===========================================================================
stage_play:
        mov     dx, offset msg_stage_p
        mov     ah, 09h
        int     21h

        call    icon_mode_01            ; same video state as ICON play

main_loop:
        call    clear_b800
        call    blit_viewport
        call    blit_objects            ; ground sword/gold before hero
        call    blit_hero
        call    blit_equip              ; hand blade after hero body
        call    blit_hud                ; gold count strip

        xor     ah, ah
        int     16h
        cmp     ah, 01h
        je      do_exit
        cmp     ah, 48h
        je      key_up
        ; scancode 50h = Down arrow — must check before ASCII 'P' path
        cmp     ah, 50h
        je      key_dn
        cmp     ah, 4Bh
        je      key_lf
        cmp     ah, 4Dh
        je      key_rt
        cmp     al, 'r'
        je      key_rst
        cmp     al, 'R'
        je      key_rst
        cmp     al, '1'
        je      key_h0
        cmp     al, '2'
        je      key_h1
        cmp     al, '3'
        je      key_h2
        cmp     al, '4'
        je      key_h3
        ; ICON1: key &= 5Fh then cmp 50h → P/p both pick
        mov     bl, al
        and     bl, 5Fh
        cmp     bl, 'P'
        je      key_pickup
        cmp     bl, 'G'
        je      key_gold_demo
        jmp     main_loop

key_up:
        cmp     word ptr cam_y, 0
        je      main_loop
        dec     word ptr cam_y
        cmp     byte ptr steps_south, 0
        je      main_loop
        dec     byte ptr steps_south
        jmp     main_loop
key_dn:
        cmp     word ptr cam_y, 96
        jae     main_loop
        inc     word ptr cam_y
        inc     byte ptr steps_south
        jmp     main_loop
key_lf:
        cmp     word ptr cam_x, 0
        je      main_loop
        dec     word ptr cam_x
        jmp     main_loop
key_rt:
        cmp     word ptr cam_x, 18
        jae     main_loop
        inc     word ptr cam_x
        jmp     main_loop
key_rst:
        mov     byte ptr steps_south, 0
        cmp     byte ptr mode_rt, 0
        je      rst_file
        mov     word ptr cam_x, CAM_X0_RT
        mov     word ptr cam_y, CAM_Y0_RT
        jmp     main_loop
rst_file:
        mov     word ptr cam_x, CAM_X0_FILE
        mov     word ptr cam_y, CAM_Y0_FILE
        jmp     main_loop

; P: pick sword if "near" (steps_south >= 7 ≈ spawn y+7 → tile y=10)
; Live 2026-07-20: long Down×10–12 clears ground sword; 6 was often short.
; Matches LA.DAT slot 91 (3,10). Full AABB not simmed.
key_pickup:
        cmp     byte ptr sword_alive, 0
        je      main_loop
        cmp     byte ptr steps_south, 7
        jb      main_loop               ; arm-reach only if not far enough south
        mov     byte ptr sword_alive, 0
        mov     byte ptr sword_equipped, 1
        jmp     main_loop

; G: demo gold pickup (real gold needs on-tile AABB vs type 2BEA)
key_gold_demo:
        mov     al, gold_count
        cmp     al, gold_quota
        jae     main_loop
        cmp     byte ptr gold_alive0, 0
        je      gold_try1
        mov     byte ptr gold_alive0, 0
        inc     byte ptr gold_count
        jmp     main_loop
gold_try1:
        cmp     byte ptr gold_alive1, 0
        je      main_loop
        mov     byte ptr gold_alive1, 0
        inc     byte ptr gold_count
        jmp     main_loop

key_h0:
        mov     byte ptr hero_state, 0
        jmp     main_loop
key_h1:
        mov     byte ptr hero_state, 1
        jmp     main_loop
key_h2:
        mov     byte ptr hero_state, 2
        jmp     main_loop
key_h3:
        mov     byte ptr hero_state, 3
        jmp     main_loop

do_exit:
        mov     ax, 0003h
        int     10h
        mov     dx, offset msg_bye
        mov     ah, 09h
        int     21h
        cmp     byte ptr mode_rt, 0
        je      bye_file
        mov     dx, offset msg_bye_rt
        jmp     bye_print
bye_file:
        mov     dx, offset msg_bye_file
bye_print:
        mov     ah, 09h
        int     21h
        mov     ax, 4C00h
        int     21h

exit_err:
        mov     ax, 0003h
        int     10h
        mov     ax, 4C01h
        int     21h

; ---------------------------------------------------------------------------
; icon_mode_01 - safe subset of ICON.EXE video setup
;   INT 10: mode 00 then 01
;   AX=1102: ROM 8x8 font into blocks 0 and 1 (EGA/VGA)
;
; NOTE: ICON also pokes CRTC 09=81h + ATC. Doing that alone in DOSBox
; shrinks cells so only a thin band at the top is visible (world map
; mostly black). Full CRTC state needs a live register dump; until then
; mode + font only.
; ---------------------------------------------------------------------------
icon_mode_01:
        push    ax
        push    bx

        mov     ax, 0000h
        int     10h
        mov     ax, 0001h
        int     10h

        ; Probe EGA/VGA font services (ICON: AX=1130 BH=FFh)
        mov     ax, 1130h
        mov     bh, 0FFh
        int     10h
        cmp     bh, 0FFh
        je      im01_done

        mov     ax, 1102h               ; load ROM 8x8
        xor     bx, bx                  ; block 0
        int     10h
        mov     ax, 1102h
        mov     bx, 0001h               ; block 1
        int     10h

im01_done:
        pop     bx
        pop     ax
        ret

; ---------------------------------------------------------------------------
; bake_stamp_file (ICON0 sub_32 @ 0ADA / loop 0B33)
;   SI = DI = raw file buffer (BA.DAT or BB.DAT)
;   BX = region size (2304)
;   File: byte0 = stamp count N, then N*24 bytes already char,attr
;   Packs into DI..DI+BX-1; zero-fills remainder.
; ---------------------------------------------------------------------------
bake_stamp_file:
        push    ax
        push    bx
        push    cx
        push    dx
        push    si
        push    di

        mov     al, [si]
        xor     ah, ah                  ; N
        mov     cx, STAMP_BYTES
        mul     cx                      ; AX = N*24 (DX may be clobbered)
        mov     cx, ax
        mov     dx, bx                  ; region size
        cmp     cx, dx
        jbe     bsf_len_ok
        mov     cx, dx
bsf_len_ok:
        mov     ax, dx
        dec     ax                      ; max payload after count byte
        cmp     cx, ax
        jbe     bsf_do
        mov     cx, ax
bsf_do:
        push    cx                      ; payload bytes
        inc     si
        rep     movsb
        pop     ax                      ; payload
        mov     cx, dx
        sub     cx, ax                  ; remaining to zero
        jz      bsf_done
        xor     al, al
        rep     stosb
bsf_done:
        pop     di
        pop     si
        pop     dx
        pop     cx
        pop     bx
        pop     ax
        ret

; ---------------------------------------------------------------------------
; decode_map_rle (ICON0 MAP load ~1223..1305)
;   map_raw = on-disk L*.MAP (RLE, often padded to MAP_SIZE)
;   map_buf = expanded stamp ids (MAP_SIZE bytes)
;   b <= 7Fh: literal, prev=b
;   b >  7Fh: emit (b&7Fh - 1) extra copies of prev  (total run length = n)
; ---------------------------------------------------------------------------
decode_map_rle:
        push    ax
        push    bx
        push    cx
        push    dx
        push    si
        push    di

        mov     si, offset map_raw
        mov     di, offset map_buf
        mov     cx, MAP_SIZE            ; dest remaining
        mov     dx, MAP_SIZE            ; src remaining
        xor     bl, bl                  ; prev

dmr_loop:
        jcxz    dmr_done
        or      dx, dx
        jz      dmr_pad
        lodsb
        dec     dx
        cmp     al, 80h
        jae     dmr_run
        stosb
        mov     bl, al
        dec     cx
        jmp     dmr_loop

dmr_run:
        and     al, 7Fh                 ; n
        jz      dmr_loop                ; n=0 → no extra
        dec     al                      ; emit n-1 copies
        jz      dmr_loop
        mov     bh, al                  ; count
dmr_rep:
        jcxz    dmr_done
        mov     al, bl
        stosb
        dec     cx
        dec     bh
        jnz     dmr_rep
        jmp     dmr_loop

dmr_pad:
        xor     al, al
        rep     stosb
dmr_done:
        pop     di
        pop     si
        pop     dx
        pop     cx
        pop     bx
        pop     ax
        ret

; ---------------------------------------------------------------------------
; load_frames: DX -> ASCIZ path, BX -> dest buffer
;   Reads up to MAX_FRAMES * SCR_SIZE bytes via handle I/O.
;   Returns AL = frame count (0 if open/read failed).
; ---------------------------------------------------------------------------
load_frames:
        push    bx
        push    cx
        push    dx
        push    si
        push    di

        mov     si, bx                  ; dest base
        mov     ax, 3D00h               ; open read-only
        int     21h
        jc      lf_fail
        mov     bx, ax                  ; handle

        xor     di, di                  ; frame count
lf_loop:
        cmp     di, MAX_FRAMES
        jae     lf_close

        ; dest = si + di * SCR_SIZE
        mov     ax, di
        mov     cx, SCR_SIZE
        mul     cx                      ; DX:AX
        add     ax, si
        mov     dx, ax                  ; buffer offset

        push    bx
        mov     ah, 3Fh
        mov     cx, SCR_SIZE
        int     21h                     ; BX=handle, DX=buf, CX=2000
        pop     bx
        jc      lf_close
        cmp     ax, SCR_SIZE
        jb      lf_close                ; short read = EOF
        inc     di
        jmp     lf_loop

lf_close:
        mov     ah, 3Eh
        int     21h                     ; close BX
        mov     ax, di
        jmp     lf_done
lf_fail:
        xor     ax, ax
lf_done:
        pop     di
        pop     si
        pop     dx
        pop     cx
        pop     bx
        ret

; ---------------------------------------------------------------------------
; play_frames: AL=nframes, BX=buffer base. Loop until ESC.
; ---------------------------------------------------------------------------
play_frames:
        push    ax
        push    bx
        push    cx
        push    dx
        push    si

        mov     byte ptr frame_i, 0
        cmp     al, 0
        jne     pf_ok
        mov     al, 1
pf_ok:
        mov     dl, al                  ; DL = nframes

pf_loop:
        ; SI = BX + frame_i * SCR_SIZE
        mov     al, frame_i
        xor     ah, ah
        push    dx
        mov     cx, SCR_SIZE
        mul     cx
        pop     dx
        add     ax, bx
        mov     si, ax
        call    blit_scr_page

        ; delay FRAME_DELAY ticks, abort on ESC
        call    wait_frame_or_esc
        jc      pf_done                 ; ESC

        inc     byte ptr frame_i
        mov     al, frame_i
        cmp     al, dl
        jb      pf_loop
        mov     byte ptr frame_i, 0
        jmp     pf_loop

pf_done:
        pop     si
        pop     dx
        pop     cx
        pop     bx
        pop     ax
        ret

; ---------------------------------------------------------------------------
; wait_frame_or_esc: wait FRAME_DELAY timer ticks. CF=1 if ESC pressed.
; ---------------------------------------------------------------------------
wait_frame_or_esc:
        push    ax
        push    bx
        push    cx
        push    es
        mov     ax, 0040h
        mov     es, ax
        mov     bx, word ptr es:[006Ch] ; timer low
wfe_loop:
        mov     ah, 01h                 ; key waiting?
        int     16h
        jz      wfe_notkey
        xor     ah, ah
        int     16h
        cmp     ah, 01h                 ; ESC scan
        je      wfe_esc
wfe_notkey:
        mov     ax, word ptr es:[006Ch]
        sub     ax, bx
        cmp     ax, FRAME_DELAY
        jb      wfe_loop
        clc
        jmp     wfe_done
wfe_esc:
        stc
wfe_done:
        pop     es
        pop     cx
        pop     bx
        pop     ax
        ret

; ---------------------------------------------------------------------------
; blit_scr_page: SI -> 2000-byte char,attr page -> B800:0000
; ---------------------------------------------------------------------------
blit_scr_page:
        push    es
        push    di
        push    cx
        push    si
        mov     ax, 0B800h
        mov     es, ax
        xor     di, di
        mov     cx, SCR_SIZE / 2
        rep     movsw
        pop     si
        pop     cx
        pop     di
        pop     es
        ret

; ---------------------------------------------------------------------------
; FCB helpers
; ---------------------------------------------------------------------------
fcb_open:
        mov     ah, 0Fh
        int     21h
        cmp     al, 0
        je      fcb_open_ok
        stc
        ret
fcb_open_ok:
        mov     bx, dx
        mov     word ptr [bx+14], 128   ; record size
        mov     word ptr [bx+12], 0     ; current block
        mov     byte ptr [bx+32], 0     ; current record
        clc
        ret

; DX=FCB, BX=dest, CX=#records
fcb_read_all:
fcb_rd_loop:
        push    cx
        push    dx
        mov     dx, bx
        mov     ah, 1Ah                 ; set DTA
        int     21h
        pop     dx
        push    dx
        mov     ah, 14h                 ; sequential read
        int     21h
        pop     dx
        add     bx, 128
        pop     cx
        loop    fcb_rd_loop
        ret

; DX=FCB, CX=#records - read into dta_scratch, discard (OVL traffic)
fcb_read_discard:
fcb_disc_loop:
        push    cx
        push    dx
        mov     dx, offset dta_scratch
        mov     ah, 1Ah
        int     21h
        pop     dx
        push    dx
        mov     ah, 14h
        int     21h
        pop     dx
        pop     cx
        loop    fcb_disc_loop
        ret

; ---------------------------------------------------------------------------
clear_b800:
        push    es
        push    di
        push    cx
        mov     ax, 0B800h
        mov     es, ax
        xor     di, di
        mov     cx, 40*25
        xor     ax, ax
        rep     stosw
        pop     cx
        pop     di
        pop     es
        ret

; ---------------------------------------------------------------------------
; blit_viewport - ICON1 strip path (sub_83-equivalent, direct to B800)
;   map_byte = map[(cam_x+i)*100 + (cam_y+sr)]
;   si = bank + map_byte*24
;   6 rows x 2 words  (same as sub_83 @ 2B9A)
;   col 39 = half-width (one cell / row) like strip edge path ~9522
; ---------------------------------------------------------------------------
blit_viewport:
        push    es
        mov     ax, 0B800h
        mov     es, ax

        xor     bp, bp                  ; sr
blit_sr:
        cmp     bp, VIEW_H
        jae     blit_done

        xor     si, si                  ; sc
blit_sc:
        cmp     si, VIEW_W
        jae     blit_half

        mov     ax, si
        add     ax, cam_x
        mov     bx, MAP_STRIDE
        mul     bx
        add     ax, cam_y
        add     ax, bp
        mov     bx, ax
        mov     al, byte ptr [map_buf+bx]
        xor     ah, ah
        mov     bl, STAMP_COUNT
        div     bl
        mov     al, ah
        xor     ah, ah
        mov     bx, STAMP_BYTES
        mul     bx
        add     ax, offset bank_buf
        mov     di, ax

        mov     ax, bp
        mov     bx, 6
        mul     bx
        add     ax, ROW0
        mov     cx, ax

        mov     ax, si
        shl     ax, 1
        add     ax, COL0
        mov     dx, ax

        push    si
        push    bp
        xor     bp, bp
blit_r:
        cmp     bp, 6
        jae     blit_stamp_done
        mov     ax, cx
        add     ax, bp
        cmp     ax, 25
        jae     blit_r_next
        push    dx
        mov     bx, 40
        mul     bx
        pop     dx
        add     ax, dx
        shl     ax, 1
        mov     bx, ax
        mov     ax, word ptr [di]
        mov     word ptr es:[bx], ax
        mov     ax, word ptr [di+2]
        mov     word ptr es:[bx+2], ax
blit_r_next:
        add     di, 4
        inc     bp
        jmp     blit_r
blit_stamp_done:
        pop     bp
        pop     si
        inc     si
        jmp     blit_sc

blit_half:
        mov     ax, cam_x
        add     ax, VIEW_W
        mov     bx, MAP_STRIDE
        mul     bx
        add     ax, cam_y
        add     ax, bp
        mov     bx, ax
        mov     al, byte ptr [map_buf+bx]
        xor     ah, ah
        mov     bl, STAMP_COUNT
        div     bl
        mov     al, ah
        xor     ah, ah
        mov     bx, STAMP_BYTES
        mul     bx
        add     ax, offset bank_buf
        mov     di, ax

        mov     ax, bp
        mov     bx, 6
        mul     bx
        add     ax, ROW0
        mov     cx, ax

        push    bp
        xor     bp, bp
half_r:
        cmp     bp, 6
        jae     half_done
        mov     ax, cx
        add     ax, bp
        cmp     ax, 25
        jae     half_next
        mov     bx, 40
        mul     bx
        add     ax, 39
        shl     ax, 1
        mov     bx, ax
        mov     ax, word ptr [di]
        mov     word ptr es:[bx], ax
half_next:
        add     di, 4
        inc     bp
        jmp     half_r
half_done:
        pop     bp
        inc     bp
        jmp     blit_sr

blit_done:
        pop     es
        ret

; ---------------------------------------------------------------------------
; blit_hero - live-captured pose @ (HERO_COL, HERO_ROW0..+4)
;   state 0: healthy attrs from dump
;   state 1: triangle attr -> yellow (hurt)
;   state 2: triangle attr -> red (critical)
;   state 3: skeleton-ish (yellow bones) + optional death banner row 0
; Triangle glyph TRI_CH=1Fh confirmed ICON_g0011 dump col8 row24.
; ---------------------------------------------------------------------------
blit_hero:
        push    es
        push    si
        push    di
        push    bx
        push    cx
        push    ax
        mov     ax, 0B800h
        mov     es, ax

        mov     al, hero_state
        cmp     al, 3
        je      hero_dead

        ; healthy body column (chars fixed; attrs from live except triangle)
        mov     si, offset hero_pose_ok
        call    hero_draw_pose

        ; recolor triangle cell for hurt/crit
        mov     al, hero_state
        or      al, al
        jz      hero_done
        mov     bx, (HERO_ROW0 + 4) * 80 + HERO_COL * 2
        mov     byte ptr es:[bx], TRI_CH
        cmp     byte ptr hero_state, 1
        jne     hero_crit_attr
        mov     byte ptr es:[bx+1], ATTR_HURT
        jmp     hero_done
hero_crit_attr:
        mov     byte ptr es:[bx+1], ATTR_CRIT
        jmp     hero_done

hero_dead:
        mov     si, offset hero_pose_dead
        call    hero_draw_pose
        ; short banner top row (mode 01 40-col)
        mov     si, offset msg_dead
        xor     di, di
        mov     ah, 0Eh                 ; yellow on black
hero_ban:
        lodsb
        cmp     al, '$'
        je      hero_done
        cmp     al, 0Dh
        je      hero_ban
        cmp     al, 0Ah
        je      hero_ban
        mov     es:[di], al
        mov     es:[di+1], ah
        add     di, 2
        cmp     di, 80
        jb      hero_ban

hero_done:
        pop     ax
        pop     cx
        pop     bx
        pop     di
        pop     si
        pop     es
        ret

; SI -> table: count, then count x (row_delta, col, ch, attr)  row_delta from HERO_ROW0
; Actually simpler fixed tables: list of (y, x, ch, attr) ended by 0FFh
hero_draw_pose:
        push    ax
        push    bx
        push    dx
hdp_loop:
        mov     al, [si]
        cmp     al, 0FFh
        je      hdp_done
        mov     dl, al                  ; row
        mov     dh, [si+1]              ; col
        mov     cl, [si+2]              ; ch
        mov     ch, [si+3]              ; attr
        add     si, 4
        ; offset = row*80 + col*2  (mul clobbers DX — save col)
        push    dx
        mov     al, dl
        xor     ah, ah
        mov     bx, 80
        mul     bx                      ; ax = row*80
        pop     dx
        mov     bl, dh
        xor     bh, bh
        shl     bx, 1
        add     bx, ax
        mov     es:[bx], cl
        mov     es:[bx+1], ch
        jmp     hdp_loop
hdp_done:
        pop     dx
        pop     bx
        pop     ax
        ret

; y, x, ch, attr  — live g0011 healthy; ends 0FFh
hero_pose_ok:
        db      20, 8, 02h, 70h
        db      21, 8, 2Ah, 0F1h
        db      22, 8, 09h, 0F4h
        db      23, 8, 12h, 7Fh
        db      24, 7, 0DEh, 75h        ; feet floor tint L
        db      24, 8, TRI_CH, ATTR_OK  ; triangle
        db      24, 9, 0DEh, 57h        ; feet floor tint R
        db      0FFh

; dead: same glyphs, yellow-ish attrs (skeleton stand-in)
hero_pose_dead:
        db      20, 8, 02h, ATTR_DEAD
        db      21, 8, 2Ah, ATTR_DEAD
        db      22, 8, 09h, ATTR_DEAD
        db      23, 8, 12h, ATTR_DEAD
        db      24, 7, 0DEh, 06h
        db      24, 8, TRI_CH, ATTR_DEAD
        db      24, 9, 0DEh, 06h
        db      0FFh

; Equipped: cyan blade in hand (VISUAL_APPROX from live shots after sword path)
hero_pose_equip_extra:
        db      22, 9, 0C4h, 0Bh        ; cyan bar at hand
        db      22, 10, 10h, 0Bh        ; tip
        db      0FFh

; ---------------------------------------------------------------------------
; blit_objects — ground items (VISUAL_APPROX; not in default B800 dumps)
; Sword: LA.DAT slot 91 tile (3,10) = ~6-7 south of spawn; screen-fixed approx
; Gold: ICON1 type 2BEA piles (positions from live shots, not DAT pairs)
; ---------------------------------------------------------------------------
blit_objects:
        push    es
        push    si
        push    ax
        mov     ax, 0B800h
        mov     es, ax

        cmp     byte ptr sword_alive, 0
        je      obj_gold
        mov     si, offset sword_ground_pose
        call    hero_draw_pose          ; same (y,x,ch,attr) format

obj_gold:
        cmp     byte ptr gold_alive0, 0
        je      obj_gold1
        mov     si, offset gold_pose0
        call    hero_draw_pose
obj_gold1:
        cmp     byte ptr gold_alive1, 0
        je      obj_done
        mov     si, offset gold_pose1
        call    hero_draw_pose
obj_done:
        pop     ax
        pop     si
        pop     es
        ret

; equip after hero so blade stays visible
blit_equip:
        push    es
        push    si
        push    ax
        cmp     byte ptr sword_equipped, 0
        je      beq_ret
        cmp     byte ptr hero_state, 3
        je      beq_ret
        mov     ax, 0B800h
        mov     es, ax
        mov     si, offset hero_pose_equip_extra
        call    hero_draw_pose
beq_ret:
        pop     ax
        pop     si
        pop     es
        ret

; VISUAL_APPROX: horizontal blade south of hero col (live filmstrip)
sword_ground_pose:
        db      16, 7, 0C4h, 08h        ; hilt dark
        db      16, 8, 0C4h, 0Bh        ; cyan blade
        db      16, 9, 0C4h, 0Bh
        db      16, 10, 10h, 0Bh        ; tip
        db      0FFh

; VISUAL_APPROX: coin piles (yellow/brown) — live shots lower + mid
gold_pose0:
        db      14, 12, 07h, 0Eh        ; · yellow
        db      14, 13, 04h, 06h        ; ♦ brown
        db      15, 12, 04h, 0Eh
        db      15, 13, 07h, 06h
        db      0FFh
gold_pose1:
        db      11, 18, 07h, 0Eh
        db      11, 19, 04h, 06h
        db      12, 18, 04h, 0Eh
        db      0FFh

; ---------------------------------------------------------------------------
; blit_hud — "G:n/q" gold counter (DS:2BEC / DS:5A24 concept)
; ---------------------------------------------------------------------------
blit_hud:
        push    es
        push    ax
        push    bx
        push    di
        mov     ax, 0B800h
        mov     es, ax
        xor     di, di                  ; row 0 col 0
        mov     ah, 0Eh                 ; yellow
        mov     al, 'G'
        mov     es:[di], ax
        mov     al, ':'
        mov     es:[di+2], ax
        mov     al, gold_count
        add     al, '0'
        mov     es:[di+4], ax
        mov     al, '/'
        mov     es:[di+6], ax
        mov     al, gold_quota
        add     al, '0'
        mov     es:[di+8], ax
        ; S if sword equipped
        cmp     byte ptr sword_equipped, 0
        je      hud_done
        mov     al, ' '
        mov     es:[di+10], ax
        mov     al, 'S'
        mov     ah, 0Bh                 ; cyan
        mov     es:[di+12], ax
hud_done:
        pop     di
        pop     bx
        pop     ax
        pop     es
        ret

; ---------------------------------------------------------------------------
; Buffers (after code)
; ---------------------------------------------------------------------------
dta_scratch:
        db      128 dup (0)
; Multi-frame intro pages (MAX_FRAMES * 2000 each)
scr_title:
        db      (MAX_FRAMES * SCR_SIZE) dup (0)
scr_ani:
        db      (MAX_FRAMES * SCR_SIZE) dup (0)
ladat_buf:
        db      LADAT_MAX dup (0)
madat_buf:
        db      MADAT_MAX dup (0)
bank_buf:
        db      BANK_SIZE dup (0)
map_raw:
        db      MAP_SIZE dup (0)        ; on-disk RLE L*.MAP
map_buf:
        db      MAP_SIZE dup (0)        ; expanded stamp indices

end     start
