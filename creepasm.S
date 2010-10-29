.arm
.globl _undefined_handler
_undefined_handler:
    # ldr pc, _saved
    # I don't want to figure out how to use the stack, so here is some ridiculous code
    mrs sp, spsr
    tst sp, #0x20 ;# thumb?
    ldreq pc, _saved
    ldrb sp, [lr, #-2]
    cmp sp, #0xca
    ldrne pc, _saved
    ldrb sp, [lr, #-1]
    cmp sp, #0xde
    ldrne pc, _saved
    # Fine!  It is mine then!
    # We were going to blx anyway, so R9 and R12 can get trashed
    sub lr, #2
    ldr r9, _record_start
loop:
    ldr r12, [r9]
    cmp r12, lr
    ldrne r9, [r9, #0xc]
    bne loop
    ldrh r12, [r9, #8]
    strh r12, [lr]
    and r12, #0x38
    add pc, r12
    nop
    str r0, [r9, #4]
    b end
    str r1, [r9, #4]
    b end
    str r2, [r9, #4]
    b end
    str r3, [r9, #4]
    b end
    str r4, [r9, #4]
    b end
    str r5, [r9, #4]
    b end
    str r6, [r9, #4]
    b end
    str r7, [r9, #4]
end:
    mcr p15, 0, lr, c7, c14, 1
    mcr p15, 0, lr, c7, c5, 1
    movs pc, lr

.globl _record_start, _saved
_record_start: .long 0x00000000
_saved: .long 0x00000000
deadbeef: .long 0xdeadbeef
