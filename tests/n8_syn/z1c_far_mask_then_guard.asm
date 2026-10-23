CODE1 segment para public use16 'CODE'
assume cs:CODE1
start:
    mov bx, word ptr cs:[idx]
    and bx, 7
    cmp bx, 2
    ja def
    shl bx, 1
    shl bx, 1
    jmp dword ptr cs:[bx+tbl]
def: mov ah, 4Ch
    int 21h
idx dw 1
tbl dd f0, f1, f2, d0, d1, d2, d3
CODE1 ends
CODE2 segment para public use16 'CODE'
assume cs:CODE2
f0: mov al, 0
    retf
f1: mov al, 1
    retf
f2: mov al, 2
    retf
d0 db 0B0h, 70h, 0CBh
d1 db 0B0h, 71h, 0CBh
d2 db 0B0h, 72h, 0CBh
d3 db 0B0h, 73h, 0CBh
CODE2 ends
STK segment para stack 'STACK'
    db 256 dup (0)
STK ends
end start
