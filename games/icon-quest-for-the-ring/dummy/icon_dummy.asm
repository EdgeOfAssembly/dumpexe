; icon_dummy.asm — ICON terrain stub (UASM)  v3
;
; Goal: same draw path as ICON1 (map index → stamp → B800), not file→PNG.
; After this is solid, a host PNG tool can reuse the same blit rules.
;
; Load order:
;   1) STAMPS.BIN + MAPRT.BIN  (optional runtime dumps → near byte-id vs live ICON)
;   2) else BA.DAT [+BB.DAT] + LA.MAP  (on-disk; BA skip leading 5Ah → char,attr)
;
; Draw (ICON1-faithful):
;   clear B800 to 00,00
;   for strip_row 0..3, stamp_col 0..18:
;     id = map[(cam_x+sc)*100 + (cam_y+sr)]
;     blit 2×6 cells at (col=1+sc*2, row=2+sr*6) from bank+id*24 (char,attr)
;   half-stamp at map x=cam_x+19 → column 39 only (live B800 right edge)
;
; Keys: arrows camera, R reset, ESC quit
;
; Build:  uasm -bin -Fo icon_dummy.com icon_dummy.asm
; Run:    from ICON/ (data files beside COM)
;
.8086
.model tiny
.code
org     100h

start:
        jmp     main

; ---------------------------------------------------------------------------
MAP_STRIDE      equ     100
STAMP_BYTES     equ     24
STAMP_COUNT     equ     192             ; 96+96; ids mod this
VIEW_W          equ     19              ; full 2-cell stamps (ICON i=0..12h)
VIEW_H          equ     4
COL0            equ     1
ROW0            equ     2
CAM_X0_FILE     equ     7               ; cold start on LA.MAP
CAM_Y0_FILE     equ     75
CAM_X0_RT       equ     0               ; runtime map already scrolled
CAM_Y0_RT       equ     0

BA_SIZE         equ     2304
BB_SIZE         equ     2304
BANK_SIZE       equ     BA_SIZE + BB_SIZE
MAP_SIZE        equ     3840

; ---------------------------------------------------------------------------
msg_boot        db      'ICON dummy v3: draw path + optional RT dumps.',0Dh,0Ah,'$'
msg_rt          db      'Loaded STAMPS.BIN + MAPRT.BIN (parity mode).',0Dh,0Ah,'$'
msg_file        db      'Loaded BA/BB + LA.MAP (file mode, BA bake).',0Dh,0Ah,'$'
msg_no_ba       db      'FCB open BA.DAT failed.',0Dh,0Ah,'$'
msg_no_map      db      'FCB open LA.MAP / MAPRT.BIN failed.',0Dh,0Ah,'$'
msg_bye         db      0Dh,0Ah,'ICON dummy exit. mode was: $'
msg_bye_rt      db      'parity (STAMPS+MAPRT)',0Dh,0Ah,'$'
msg_bye_file    db      'file (BA/BB+LA.MAP)',0Dh,0Ah,'$'

; FCB: drive, 8.3 name, 25 reserved (UASM: split db lines)
fcb_stamps:
        db      0
        db      'STAMPS  '
        db      'BIN'
        db      25 dup (0)
fcb_maprt:
        db      0
        db      'MAPRT   '
        db      'BIN'
        db      25 dup (0)
fcb_ba:
        db      0
        db      'BA      '
        db      'DAT'
        db      25 dup (0)
fcb_bb:
        db      0
        db      'BB      '
        db      'DAT'
        db      25 dup (0)
fcb_map:
        db      0
        db      'LA      '
        db      'MAP'
        db      25 dup (0)

cam_x   dw      CAM_X0_FILE
cam_y   dw      CAM_Y0_FILE
mode_rt db      0                       ; 1 = STAMPS+MAPRT

; ---------------------------------------------------------------------------
main:
        push    cs
        pop     ds
        push    cs
        pop     es

        mov     dx, offset msg_boot
        mov     ah, 09h
        int     21h

        ; --- try parity dumps first ---
        mov     byte ptr mode_rt, 0
        mov     dx, offset fcb_stamps
        call    fcb_open
        jc      file_mode
        mov     dx, offset fcb_stamps
        mov     bx, offset bank_buf
        mov     cx, BANK_SIZE / 128
        call    fcb_read_all

        mov     dx, offset fcb_maprt
        call    fcb_open
        jc      file_mode_after_stamps
        mov     dx, offset fcb_maprt
        mov     bx, offset map_buf
        mov     cx, MAP_SIZE / 128
        call    fcb_read_all

        mov     byte ptr mode_rt, 1
        mov     word ptr cam_x, CAM_X0_RT
        mov     word ptr cam_y, CAM_Y0_RT
        mov     dx, offset msg_rt
        mov     ah, 09h
        int     21h
        jmp     go_video

file_mode_after_stamps:
        ; STAMPS without MAPRT → fall through to full file mode
file_mode:
        ; --- BA.DAT required ---
        mov     dx, offset fcb_ba
        call    fcb_open
        jc      err_ba
        mov     dx, offset fcb_ba
        mov     bx, offset bank_buf
        mov     cx, BA_SIZE / 128
        call    fcb_read_all
        call    bake_ba                 ; drop 5Ah; body is char,attr

        ; --- BB.DAT optional ---
        mov     dx, offset fcb_bb
        call    fcb_open
        jc      bb_zero
        mov     dx, offset fcb_bb
        mov     bx, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE / 128
        call    fcb_read_all
        ; bake BB the same way (leading 5Ah)
        push    si
        push    di
        push    cx
        mov     si, offset bank_buf + BA_SIZE + 1
        mov     di, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE - 1
        rep     movsb
        mov     byte ptr [di], 0
        pop     cx
        pop     di
        pop     si
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
        mov     dx, offset msg_file
        mov     ah, 09h
        int     21h
        jmp     go_video

err_ba:
        call    fail_mode3
        mov     dx, offset msg_no_ba
        mov     ah, 09h
        int     21h
        jmp     exit_err
err_map:
        call    fail_mode3
        mov     dx, offset msg_no_map
        mov     ah, 09h
        int     21h
        jmp     exit_err

; ---------------------------------------------------------------------------
; bake_ba: BA.DAT on disk is 5Ah + char,attr stream (live DS:207A stamps 0..90).
; Shift bank_buf left by 1 within the BA half.
; ---------------------------------------------------------------------------
bake_ba:
        push    si
        push    di
        push    cx
        mov     si, offset bank_buf + 1
        mov     di, offset bank_buf
        mov     cx, BA_SIZE - 1
        rep     movsb
        mov     byte ptr [di], 0        ; pad last
        pop     cx
        pop     di
        pop     si
        ret

; ---------------------------------------------------------------------------
go_video:
        mov     ax, 0001h               ; mode 01h 40×25
        int     10h

main_loop:
        call    clear_b800
        call    blit_viewport

        xor     ah, ah
        int     16h
        cmp     ah, 01h                 ; ESC
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
        cmp     word ptr cam_x, 18      ; room for sc 0..18 and half at +19
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
        ; Mode-set wipes the pre-video banner — report mode here in 80-col text.
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
        mov     ax, 4C01h
        int     21h

fail_mode3:
        push    ax
        mov     ax, 0003h
        int     10h
        pop     ax
        ret

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
        mov     word ptr [bx+14], 128
        mov     word ptr [bx+12], 0
        mov     byte ptr [bx+32], 0
        clc
        ret

; DX=FCB, BX=dest, CX=#records
fcb_read_all:
fcb_rd_loop:
        push    cx
        push    dx
        mov     dx, bx
        mov     ah, 1Ah
        int     21h
        pop     dx
        push    dx
        mov     ah, 14h
        int     21h
        pop     dx
        add     bx, 128
        pop     cx
        loop    fcb_rd_loop
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
; blit_viewport — ICON1 grid + col-39 half stamp
; bank_buf cells are already char,attr (runtime order)
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
        jae     blit_half               ; after 19 full stamps → col 39

        ; map index = (cam_x+sc)*100 + (cam_y+sr)
        mov     ax, si
        add     ax, cam_x
        mov     bx, MAP_STRIDE
        mul     bx                      ; DX:AX  (save DX around later mul)
        add     ax, cam_y
        add     ax, bp
        mov     bx, ax
        mov     al, byte ptr [map_buf+bx]
        xor     ah, ah
        mov     bl, STAMP_COUNT
        div     bl                      ; AH = id mod 192
        mov     al, ah
        xor     ah, ah

        ; DI → stamp in bank (char,attr pairs)
        mov     bx, STAMP_BYTES
        mul     bx
        add     ax, offset bank_buf
        mov     di, ax

        ; base row / col
        mov     ax, bp
        mov     bx, 6
        mul     bx
        add     ax, ROW0
        mov     cx, ax                  ; row base

        mov     ax, si
        shl     ax, 1
        add     ax, COL0
        mov     dx, ax                  ; col

        push    si
        push    bp
        xor     bp, bp                  ; r within stamp
blit_r:
        cmp     bp, 6
        jae     blit_stamp_done

        mov     ax, cx
        add     ax, bp
        cmp     ax, 25
        jae     blit_r_next

        push    dx
        mov     bx, 40
        mul     bx                      ; clobbers DX
        pop     dx
        add     ax, dx
        shl     ax, 1
        mov     bx, ax                  ; B800 offset

        ; already char,attr in bank
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

; --- half stamp: map x = cam_x+19 → column 39, left cell only ---
blit_half:
        mov     ax, cam_x
        add     ax, VIEW_W              ; +19
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
        mov     cx, ax                  ; row base

        push    bp
        xor     bp, bp
half_r:
        cmp     bp, 6
        jae     half_done
        mov     ax, cx
        add     ax, bp
        cmp     ax, 25
        jae     half_next
        push    dx
        mov     bx, 40
        mul     bx
        pop     dx
        add     ax, 39                  ; column 39
        shl     ax, 1
        mov     bx, ax
        mov     ax, word ptr [di]       ; left cell only
        mov     word ptr es:[bx], ax
half_next:
        add     di, 4
        inc     bp
        jmp     half_r
half_done:
        pop     bp

blit_sr_next:
        inc     bp
        jmp     blit_sr

blit_done:
        pop     es
        ret

; ---------------------------------------------------------------------------
bank_buf:
        db      BANK_SIZE dup (0)
map_buf:
        db      MAP_SIZE dup (0)

end     start
