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
; Constants (ICON1 terrain)
; ---------------------------------------------------------------------------
MAP_STRIDE      equ     100
STAMP_BYTES     equ     24
STAMP_COUNT     equ     192
VIEW_W          equ     19
VIEW_H          equ     4
COL0            equ     1
ROW0            equ     2
CAM_X0_FILE     equ     7
CAM_Y0_FILE     equ     75
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
msg_banner      db      'ICON dummy loader v5 - stages + multi-frame intro',0Dh,0Ah
                db      'TITLE loop -> ANI loop -> OVL0 -> assets -> OVL1 -> PLAY',0Dh,0Ah
                db      'ESC skips loops; arrows in PLAY; ESC quits PLAY.',0Dh,0Ah,'$'
msg_stage_t     db      '[stage] TITLE (TITLES.BIN multi-frame loop)',0Dh,0Ah,'$'
msg_stage_a     db      '[stage] ANI (ANIS.BIN multi-frame loop)',0Dh,0Ah,'$'
msg_stage_0     db      '[stage] ICON0.OVL FCB block-read',0Dh,0Ah,'$'
msg_stage_as    db      '[stage] BA/BB + LA.MAP + LA.DAT + MA.DAT',0Dh,0Ah,'$'
msg_stage_rt    db      '[stage] assets: STAMPS.BIN + MAPRT.BIN (parity)',0Dh,0Ah,'$'
msg_stage_1     db      '[stage] ICON1.OVL FCB block-read',0Dh,0Ah,'$'
msg_stage_p     db      '[stage] PLAY (terrain)',0Dh,0Ah,'$'
msg_no_title    db      '(no TITLES.BIN/TITLE.BIN - blank title)',0Dh,0Ah,'$'
msg_no_ani      db      '(no ANIS.BIN/ANI.BIN - blank ani)',0Dh,0Ah,'$'
msg_no_ovl0     db      'FCB open ICON0.OVL failed (continuing).',0Dh,0Ah,'$'
msg_no_ovl1     db      'FCB open ICON1.OVL failed (continuing).',0Dh,0Ah,'$'
msg_no_ba       db      'FCB open BA.DAT failed.',0Dh,0Ah,'$'
msg_no_map      db      'FCB open LA.MAP failed.',0Dh,0Ah,'$'
msg_bye         db      0Dh,0Ah,'ICON dummy exit. last stage play; mode was: $'
msg_bye_rt      db      'parity tables',0Dh,0Ah,'$'
msg_bye_file    db      'file BA+LA.MAP',0Dh,0Ah,'$'

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
        call    bake_ba

        mov     dx, offset fcb_bb
        call    fcb_open
        jc      bb_zero
        mov     dx, offset fcb_bb
        mov     bx, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE / 128
        call    fcb_read_all
        ; bake BB (drop leading 5Ah)
        mov     si, offset bank_buf + BA_SIZE + 1
        mov     di, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE - 1
        rep     movsb
        mov     byte ptr [di], 0
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
        mov     dx, offset fcb_map
        mov     bx, offset map_buf
        mov     cx, MAP_SIZE / 128
        call    fcb_read_all
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

        xor     ah, ah
        int     16h
        cmp     ah, 01h
        je      do_exit
        cmp     ah, 48h
        je      key_up
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
        jmp     main_loop

key_up:
        cmp     word ptr cam_y, 0
        je      main_loop
        dec     word ptr cam_y
        jmp     main_loop
key_dn:
        cmp     word ptr cam_y, 96
        jae     main_loop
        inc     word ptr cam_y
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
        cmp     byte ptr mode_rt, 0
        je      rst_file
        mov     word ptr cam_x, CAM_X0_RT
        mov     word ptr cam_y, CAM_Y0_RT
        jmp     main_loop
rst_file:
        mov     word ptr cam_x, CAM_X0_FILE
        mov     word ptr cam_y, CAM_Y0_FILE
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
; bake_ba: disk BA = 5Ah + char,attr stream -> bank_buf char,attr
; ---------------------------------------------------------------------------
bake_ba:
        push    si
        push    di
        push    cx
        mov     si, offset bank_buf + 1
        mov     di, offset bank_buf
        mov     cx, BA_SIZE - 1
        rep     movsb
        mov     byte ptr [di], 0
        pop     cx
        pop     di
        pop     si
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
; blit_viewport - ICON1: 19 full stamps + col-39 half (char,attr bank)
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
map_buf:
        db      MAP_SIZE dup (0)

end     start
