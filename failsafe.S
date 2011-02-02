# int run_failsafe(&result, func, a1, a2)

.arm
.globl _run_failsafe
_run_failsafe:
    push {r4-r8, r10, r11, lr}
    mov r4, r0
    mov r5, r1
    
    # steal the offset in the thread struct from copyout
    ldr r11, copyout_pcrel
copyout_origin:
    ldr r11, [pc, r11]
    #mov r0, r11
    #pop {r4-r8, r10, r11, pc}
    ldr r11, [r11, #0x1c]
    lsl r11, r11, #20
    mrc p15, 0, r0, c13, c0, 4
    add r11, r0, r11, lsr#20

    ldr r6, deadbeef
    ldr r8, [r11]
    push {r6, r8, r11}
    adr r6, oops
    str r6, [r11]

    mov r0, r2
    mov r1, r3

    blx r5

    # okay, it worked
    mrc p15, 0, r1, c13, c0, 4
    str r8, [r11]

    cmp r4, #0
    strne r0, [r4]

    mov r0, #0
    pop {r1, r2, r3, r4-r8, r10, r11, pc}

oops:
    # it failed; try to find our stack frame
    # but first- we might have gotten here in thumb mode
    .long 0xe3a04778 ;# bx pc / mov r4, #0x1e00000
    ldr r0, deadbeef
loop:
    pop {r1}
    cmp r0, r1
    bne loop

    # found it
    # don't leave it sitting in the stack, though
    mov r1, #0
    str r1, [sp, #-4]
    
    pop {r1, r2, r4-r8, r10, r11, lr}
    str r1, [r2]

    mov r0, #-1
    bx lr

deadbeef: .long 0xbeefdead
copyout_pcrel: .long L_copyout$non_lazy_ptr-8-(copyout_origin)
	.non_lazy_symbol_pointer
L_copyout$non_lazy_ptr:
	.indirect_symbol _copyout
	.long	0
	.subsections_via_symbols
