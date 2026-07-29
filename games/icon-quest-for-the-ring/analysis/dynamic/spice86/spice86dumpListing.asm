017D:0000 call near 0x652B
017D:652B mov AX,CS
017D:652D add AX,word ptr CS:[3]
017D:6532 add AX,word ptr CS:[5]
017D:6537 add AX,word ptr CS:[7]
017D:653C add AX,word ptr CS:[9]
017D:6541 cmp AX,word ptr DS:[2]
017D:6545 jbe short 0x6568
017D:6547 push DS
017D:6548 call near 0x655B
017D:655B mov AX,CS
017D:655D mov DS,AX
017D:655F pop DX
017D:6560 mov AH,9
017D:6562 int 0x21
017D:6568 mov AX,CS
017D:656A add AX,word ptr CS:[3]
017D:656F mov ES,AX
017D:6571 mov DI,0
017D:6574 mov SI,DI
017D:6576 cld
017D:6577 mov CX,0x0100
017D:657A rep movs byte ptr ES:[DI],byte ptr DS:[SI]
017D:657C mov word ptr ES:[0x0040],DS
017D:6581 mov DS,AX
017D:6583 mov word ptr DS:[9],DS
017D:6587 add AX,word ptr CS:[5]
017D:658C mov word ptr DS:[0x000F],AX
017D:658F add AX,word ptr CS:[9]
017D:6594 mov word ptr DS:[0x0015],AX
017D:6597 mov CX,4
017D:659A mov BX,word ptr CS:[7]
017D:659F shl BX,CL
017D:65A1 mov word ptr DS:[0x0012],BX
017D:65A5 pushf
017D:65A6 pop DX
017D:65A7 cli
017D:65A8 mov SS,AX
017D:65AA mov SP,BX
017D:65AC sti
F000:0006 callback 8
F000:000A int 0x1C
F000:000C callback 0x0101
F000:0010 iret
F000:0011 callback 9
F000:0015 iret
F000:0057 callback 0x0070
F000:005B iret
F000:005D call far F000:00E3
F000:0062 callback 0x0074
F000:0066 iret
F000:0067 callback 0x0104
F000:006B iret
F000:006C callback 0x0105
F000:0070 iret
F000:0071 callback 0x0106
F000:0075 iret
F000:0076 callback 0x0107
F000:007A iret
F000:007B callback 0x0108
F000:007F iret
F000:0080 callback 0x0109
F000:0084 iret
F000:00E2 ret far
F000:00E3 callback 0x010C
F000:00E7 call far F000:00E2
F000:00EC callback 0x010D
F000:00F0 ret far
