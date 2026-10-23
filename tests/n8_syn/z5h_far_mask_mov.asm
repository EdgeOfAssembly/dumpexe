CODE1 segment para public use16 'CODE'
assume cs:CODE1
start:
    mov bx, word ptr cs:[idx]
    cmp bx, 1
    ja def
    and bx, 3
    mov bx, word ptr cs:[idx]
    shl bx, 1
    shl bx, 1
    jmp dword ptr cs:[bx+tbl]
def: mov ah, 4Ch
    int 21h
idx dw 1
tbl dd f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, d0, d1, d2, d3
CODE1 ends
CODE2 segment para public use16 'CODE'
assume cs:CODE2
f0: mov al, 0
    retf
f1: mov al, 1
    retf
f2: mov al, 2
    retf
f3: mov al, 3
    retf
f4: mov al, 4
    retf
f5: mov al, 5
    retf
f6: mov al, 6
    retf
f7: mov al, 7
    retf
f8: mov al, 8
    retf
f9: mov al, 9
    retf
f10: mov al, 10
    retf
f11: mov al, 11
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
