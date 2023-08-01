BITS 64
    PUSH        RBP
    MOV         RBP,RSP
    SUB         RSP,0x40
    MOV         [RBP-0x14],EDI
    MOV         [RBP-0x20],RSI
    MOV         [RBP-0x28],RDX
    MOV         [RBP-0x18],ECX
    MOV         [RBP-0x30],R8
    MOV         [RBP-0x38],R9
    MOV         R8,[RBP-0x38]
    MOV         RDI,[RBP-0x30]
    MOV         ECX,[RBP-0x18]
    MOV         RDX,[RBP-0x28]
    MOV         RSI,[RBP-0x20]
    MOV         EAX,[RBP-0x14]
    MOV         R9,R8
    MOV         R8,RDI
    MOV         EDI,EAX
    MOV         R12,0xfffffffffffa
    CALL        R12

    MOV         [RBP-0x08],RAX

PATTERN_LOOP:
    MOV         RAX,[RBP-0x20]
    ADD         RAX,0x10
    MOV         RSI,0xffffffffff01
    MOV         RDI,RAX
    MOV         R12,0xfffffffffffb
    CALL        R12

    TEST        RAX,RAX
    JE          PATTERN_NOT_FOUND

PATTERN_MATCH:
    MOV         DWORD [RBP-0x0c],0x00
    MOV         RAX,QWORD [RBP-0x20]
    ADD         RAX,0x25
    MOV         EDX,0x00
    MOV         ESI,0x00
    MOV         RDI,RAX
    MOV         R12,0xfffffffffffc
    CALL        R12

    MOV         [RBP-0x10],EAX

RECV_LOOP:
    MOV         R8,[RBP-0x38]
    MOV         RDI,[RBP-0x30]
    MOV         ECX,[RBP-0x18]
    MOV         RDX,[RBP-0x28]
    MOV         RSI,[RBP-0x20]
    MOV         EAX,[RBP-0x14]
    MOV         R9,R8
    MOV         R8,RDI
    MOV         EDI,EAX
    MOV         R12,0xfffffffffffa
    CALL        R12

    MOV         QWORD [rbp-0x8],rax
    MOV         RAX,[rbp-0x20]
    ADD         RAX,0x25
    MOV         EDX,0x00
    MOV         ESI,0x00
    MOV         RDI,RAX
    MOV         R12,0xfffffffffffc
    CALL        R12

    MOV         DWORD [rbp-0xc],eax
    CMP         EAX,DWORD [rbp-0x10]

    JE          RECV_LOOP
    JMP         PATTERN_LOOP

PATTERN_NOT_FOUND:
    MOV         RAX,[RBP-0x08]

EXIT:
    LEAVE
    RET
