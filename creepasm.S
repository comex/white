.arm
.globl _undef_handler
_undef_handler:
    # ldr pc, _undef_saved
    # I don't want to figure out how to use the stack, so here is some ridiculous code
    mrs sp, spsr
    tst sp, #0x20 ;# thumb?
    ldreq pc, _undef_saved
    ldrb sp, [lr, #-2]
    cmp sp, #0xca
    ldrne pc, _undef_saved
    ldrb sp, [lr, #-1]
    cmp sp, #0xde
    ldrne pc, _undef_saved
    # Fine!  It is mine then!
    # We were going to blx anyway, so R9 BUT NOT R12 can get trashed
    sub lr, #2
    ldr r9, _record_start
loop:
    ldr sp, [r9]
    cmp sp, lr
    ldrne r9, [r9, #0xc]
    bne loop
    ldrh sp, [r9, #8]
    strh sp, [lr]
    and sp, #0x78
    add pc, sp
    nop
    # a few of these don't make sense
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
    b end
    str r8, [r9, #4]
    b end
    str r9, [r9, #4]
    b end
    str r10, [r9, #4]
    b end
    str r11, [r9, #4]
    b end
    str r12, [r9, #4]
    b end
    str sp, [r9, #4]
    b end
    str lr, [r9, #4]
    b end
    str pc, [r9, #4]
end:
    mcr p15, 0, lr, c7, c14, 1
    mcr p15, 0, lr, c7, c5, 1
    movs pc, lr

.globl _record_start, _undef_saved
_record_start: .long 0x00000000
_undef_saved: .long 0x00000000
deadbeef: .long 0xdeadbeef
