; icon_dummy.asm — ICON-like DOS stub (UASM)
;
; Loads BA.DAT + BB.DAT + LA.MAP (FCB), mode 01h, blits MAP stamps to B800.
; Keys: arrows move camera, R reset cam, ESC quit.
;
; Build:  uasm -bin -Fo icon_dummy.com icon_dummy.asm
; Run:    from ICON/ directory (needs BA.DAT BB.DAT LA.MAP)
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
STAMP_COUNT     equ     192             ; BA 96 + BB 96
VIEW_W          equ     19
VIEW_H          equ     4               ; rows 2,8,14,20 (clamp to <25)
COL0            equ     1
ROW0            equ     2
CAM_X0          equ     7
CAM_Y0          equ     75

BA_SIZE         equ     2304
BB_SIZE         equ     2304
BANK_SIZE       equ     BA_SIZE + BB_SIZE
MAP_SIZE        equ     3840

; ---------------------------------------------------------------------------
msg_boot        db      'ICON dummy v2: BA+BB+MAP, arrows move, ESC quit.',0Dh,0Ah,'$'
msg_no_ba       db      'FCB open BA.DAT failed.',0Dh,0Ah,'$'
msg_no_bb       db      'FCB open BB.DAT failed (continuing with BA only).',0Dh,0Ah,'$'
msg_no_map      db      'FCB open LA.MAP failed.',0Dh,0Ah,'$'
msg_bye         db      0Dh,0Ah,'ICON dummy exit.',0Dh,0Ah,'$'

; FCB: drive, 8-char name, 3-char ext, rest zero (UASM needs split db lines)
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

cam_x   dw      CAM_X0
cam_y   dw      CAM_Y0
have_bb db      0                       ; 1 if BB loaded

; ---------------------------------------------------------------------------
main:
        push    cs
        pop     ds
        push    cs
        pop     es

        mov     dx, offset msg_boot
        mov     ah, 09h
        int     21h

        ; --- load BA.DAT ---
        mov     dx, offset fcb_ba
        call    fcb_open
        jc      err_ba
        mov     dx, offset fcb_ba
        mov     bx, offset bank_buf
        mov     cx, BA_SIZE / 128
        call    fcb_read_all
        jmp     load_bb
err_ba:
        call    fail_mode3
        mov     dx, offset msg_no_ba
        mov     ah, 09h
        int     21h
        jmp     exit_err

load_bb:
        ; --- load BB.DAT (optional) into bank after BA ---
        mov     byte ptr have_bb, 0
        mov     dx, offset fcb_bb
        call    fcb_open
        jc      bb_skip
        mov     dx, offset fcb_bb
        mov     bx, offset bank_buf + BA_SIZE
        mov     cx, BB_SIZE / 128
        call    fcb_read_all
        mov     byte ptr have_bb, 1
        jmp     load_map
bb_skip:
        ; warn in mode 03 then back — keep simple: message after exit only
        ; zero-fill BB half so high ids read as empty stamps
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
        jmp     go_video
err_map:
        call    fail_mode3
        mov     dx, offset msg_no_map
        mov     ah, 09h
        int     21h
        jmp     exit_err

go_video:
        mov     ax, 0001h               ; mode 01h
        int     10h

main_loop:
        call    clear_b800
        call    blit_viewport

        ; key
        xor     ah, ah
        int     16h                     ; AL=ascii AH=scan
        cmp     ah, 01h                 ; ESC
        je      do_exit
        cmp     ah, 48h                 ; up
        je      key_up
        cmp     ah, 50h                 ; down
        je      key_dn
        cmp     ah, 4Bh                 ; left
        je      key_lf
        cmp     ah, 4Dh                 ; right
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
        cmp     word ptr cam_y, 96      ; 100-VIEW_H
        jae     main_loop
        inc     word ptr cam_y
        jmp     main_loop
key_lf:
        cmp     word ptr cam_x, 0
        je      main_loop
        dec     word ptr cam_x
        jmp     main_loop
key_rt:
        cmp     word ptr cam_x, 19      ; 38-VIEW_W
        jae     main_loop
        inc     word ptr cam_x
        jmp     main_loop
key_rst:
        mov     word ptr cam_x, CAM_X0
        mov     word ptr cam_y, CAM_Y0
        jmp     main_loop

do_exit:
        mov     ax, 0003h
        int     10h
        mov     dx, offset msg_bye
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
; fcb_open: DX = FCB, CF clear if OK (AL=0)
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

; ---------------------------------------------------------------------------
; fcb_read_all: DX=FCB, BX=dest, CX=#records of 128
; ---------------------------------------------------------------------------
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
; clear_b800: fill 40*25 words with 00,00 (not BIOS space)
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
; blit_viewport — full MAP byte index into BA||BB (mod 192)
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
        jae     blit_sr_next

        ; map index = (cam_x+sc)*100 + (cam_y+sr)
        mov     ax, si
        add     ax, cam_x
        mov     bx, MAP_STRIDE
        mul     bx                      ; DX:AX
        add     ax, cam_y
        add     ax, bp
        mov     bx, ax
        mov     al, byte ptr [map_buf+bx]
        xor     ah, ah
        ; tile %= 192
        mov     bl, STAMP_COUNT
        div     bl                      ; AH = rem
        mov     al, ah
        xor     ah, ah

        ; DI = bank_buf + tile*24
        mov     bx, STAMP_BYTES
        mul     bx
        add     ax, offset bank_buf
        mov     di, ax

        ; row = ROW0 + sr*6, col = COL0 + sc*2
        mov     ax, bp
        mov     bx, 6
        mul     bx
        add     ax, ROW0
        mov     cx, ax                  ; base row

        mov     ax, si
        shl     ax, 1
        add     ax, COL0
        mov     dx, ax                  ; col

        push    si
        push    bp
        xor     bp, bp                  ; r
blit_r:
        cmp     bp, 6
        jae     blit_stamp_done

        ; skip if row+r >= 25
        mov     ax, cx
        add     ax, bp
        cmp     ax, 25
        jae     blit_r_next

        ; offset = (row*40+col)*2 ; MUL clobbers DX
        push    dx
        mov     bx, 40
        mul     bx
        pop     dx
        add     ax, dx
        shl     ax, 1
        mov     bx, ax

        mov     al, byte ptr [di+1]
        mov     ah, byte ptr [di]
        mov     word ptr es:[bx], ax
        mov     al, byte ptr [di+3]
        mov     ah, byte ptr [di+2]
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
