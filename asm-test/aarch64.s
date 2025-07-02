    .text

OP_ADDS:
    adds x0, x0, x0
    subs x0, x0, x0
    adcs x0, x0, x0
    sbcs x0, x0, x0
    ands x0, x0, x0
    orr x0, x0, x0
    eor x0, x0, x0
    mul x0, x0, x0
    udiv x0, x0, x0
    sdiv x0, x0, x0
    lsl x0, x0, x0
    lsr x0, x0, x0
    asr x0, x0, x0

    ldr x0, rel

rel: add x0, x0, x0

    adds x0, x0, #0x123
    subs x0, x0, #0x123
    adcs x0, x0, xzr
    sbcs x0, x0, xzr

    ands x0, x0, #1
    orr x0, x0, #1
    eor x0, x0, #1
    lsl x0, x0, #1
    lsr x0, x0, #1
    asr x0, x0, #1

    ands x0, x0, #2
    orr x0, x0, #2
    eor x0, x0, #2
    lsl x0, x0, #2
    lsr x0, x0, #2
    asr x0, x0, #2

    mov x0, x0
    mvn x0, x0
    negs x0, x0
    cmp x0, x0

    adr x1, l1
    adr x1, l1
l1:
    adr x1, l1
    adr x1, l1

    blr x0
    br x0

l2:
    b.eq l2
    b.ne l2
    b.gt l2
    b.ge l2
    b.lt l2
    b.le l2
    b.hi l2
    b.hs l2
    b.lo l2
    b.ls l2

l3:
    b l3

    # ld
    ldrb w0, [x0, #0x000]
    ldrb w0, [x0, x0]
    ldrh w0, [x0, #0x000]
    ldrh w0, [x0, x0]
    ldr w0, [x0, #0x000]
    ldr w0, [x0, x0]
    ldr x0, [x0, #0x000]
    ldr x0, [x0, x0]
    ldrsb w0, [x0, #0x000]
    ldrsb w0, [x0, x0]
    ldrsh w0, [x0, #0x000]
    ldrsh w0, [x0, x0]
    ldrsw x0, [x0, #0x000]
    ldrsw x0, [x0, x0]
    ldr x0, [x0, #0x000]
    ldr x0, [x0, x0]

    # st
    strb w0, [x0, #0x000]
    strb w0, [x0, x0]
    strh w0, [x0, #0x000]
    strh w0, [x0, x0]
    str w0, [x0, #0x000]
    str w0, [x0, x0]
    str x0, [x0, #0x000]
    str x0, [x0, x0]

    # push
    str x0, [sp, #-8]!

    # pop
    ldr x0, [sp], #8

# call local
call_local:
    bl call_local

# SIMD FP
    add v0.8b, v0.8b, v0.8b
    add v0.16b, v0.16b, v0.16b
    add v0.4h, v0.4h, v0.4h
    add v0.8h, v0.8h, v0.8h
    add v0.2s, v0.2s, v0.2s
    add v0.4s, v0.4s, v0.4s
    add v0.2d, v0.2d, v0.2d
    #fadd h0, h0, h0
    fadd s0, s0, s0
    fadd d0, d0, d0
    #fadd v0.4h, v0.4h, v0.4h
    #fadd v0.8h, v0.8h, v0.8h
    fadd v0.2s, v0.2s, v0.2s
    fadd v0.4s, v0.4s, v0.4s
    fadd v0.2d, v0.2d, v0.2d

    sub v0.8b, v0.8b, v0.8b
    sub v0.16b, v0.16b, v0.16b
    sub v0.4h, v0.4h, v0.4h
    sub v0.8h, v0.8h, v0.8h
    sub v0.2s, v0.2s, v0.2s
    sub v0.4s, v0.4s, v0.4s
    sub v0.2d, v0.2d, v0.2d
    #fsub h0, h0, h0
    fsub s0, s0, s0
    fsub d0, d0, d0
    #fsub v0.4h, v0.4h, v0.4h
    #fsub v0.8h, v0.8h, v0.8h
    fsub v0.2s, v0.2s, v0.2s
    fsub v0.4s, v0.4s, v0.4s
    fsub v0.2d, v0.2d, v0.2d

OP_AND_V8:
    and v0.8b, v0.8b, v0.8b
OP_AND_V16:
    and v0.16b, v0.16b, v0.16b

OP_ORR_V8:
    orr v0.8b, v0.8b, v0.8b
OP_ORR_V16:
    orr v0.16b, v0.16b, v0.16b

OP_EOR_V8:
    eor v0.8b, v0.8b, v0.8b
OP_EOR_V16:
    eor v0.16b, v0.16b, v0.16b

OP_LSL_V8B_IMM:
    shl v0.8b, v0.8b, #0
OP_LSL_V16B_IMM:
    shl v0.16b, v0.16b, #0
OP_LSL_V4H_IMM:
    shl v0.4h, v0.4h, #0
OP_LSL_V8H_IMM:
    shl v0.8h, v0.8h, #0
OP_LSL_V2S_IMM:
    shl v0.2s, v0.2s, #0
OP_LSL_V4S_IMM:
    shl v0.4s, v0.4s, #0
OP_LSL_V2D_IMM:
    shl v0.2d, v0.2d, #0


    movi v0.8b, 0x0
    movi v0.8b, 0x1

    .inst 0x1c000000
    .inst 0x5c000000
    .inst 0x9c000000
    .inst 0xdc000000

OP_RET:
    ret
