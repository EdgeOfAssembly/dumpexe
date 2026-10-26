_TEXT segment para public use16 'CODE'
assume cs:_TEXT, ds:_TEXT
org 100h
start:
    mov si, offset prog
    mov bx, word ptr [si]
    cmp byte ptr [si+1], 9
    je other
    cmp bx, 1
    ja def
    shl bx, 1
lj: jmp word ptr [bx+tbl]
other: mov bx, 8
    jmp lj
    mov ax, 4C00h
    int 21h
def: ret
h0: mov al, 0
    ret
h1: mov al, 1
    ret
h2: mov al, 2
    ret
h3: mov al, 3
    ret
h4: mov al, 4
    ret
h5: mov al, 5
    ret
d0  db 0B0h, 70h, 0C3h
d1  db 0B0h, 71h, 0C3h
d2  db 0B0h, 72h, 0C3h
d3  db 0B0h, 73h, 0C3h
tbl dw h0, h1, d0, d1, d2, d3
prog db 1, 0
_TEXT ends
end start
