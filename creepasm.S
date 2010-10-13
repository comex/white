.arm
.globl _undefined_handler
# We were going to blx anyway, so R9 and R12 can get trashed
_undefined_handler:
    # this had better be thumb, by the way
    sub lr, #2
    ldr r9, records
loop:
    ldr r12, [r9]
    cmp r12, lr
    ldrne r9, [r9, #8]
    bne loop
    ldr r12, [r9, #4]
    strh r12, [lr, #-1]
    and r12, #0x38
    add pc, r12
    nop
    str r0, [r9, #8]
    movs pc, lr
    str r1, [r9, #8]
    movs pc, lr
    str r2, [r9, #8]
    movs pc, lr
    str r3, [r9, #8]
    movs pc, lr
    str r4, [r9, #8]
    movs pc, lr
    str r5, [r9, #8]
    movs pc, lr
    str r6, [r9, #8]
    movs pc, lr
    str r7, [r9, #8]
    movs pc, lr

records: .long records

