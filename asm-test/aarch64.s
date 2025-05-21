    .text

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
