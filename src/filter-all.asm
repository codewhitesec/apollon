BITS 64
    PUSH    R12
    MOV     R12,0xfffffffffffa
    CALL    R12

    MOV     RAX,0x00
    POP     R12
    RET
