.TEXT
.GLOBL	poly1305_init
.TYPE	poly1305_init,@function
.ALIGN	16
poly1305_init:
	lghi	%r0,0
	lghi	%r1,-1
	stg	%r0,0(%r2)
	stg	%r0,8(%r2)
	stg	%r0,16(%r2)
	clr	%r3,%r0
	je	.Ldone
	lrvg	%r4,0(%r3)
	lrvg	%r5,8(%r3)
	nihl	%r1,65472
	srlg	%r0,%r1,4
	srlg	%r1,%r1,4
	nill	%r1,65532
	ngr	%r4,%r0
	ngr	%r5,%r1
	stg	%r4,32(%r2)
	stg	%r5,40(%r2)
	larl	%r1,OPENSSL_s390xcap_P
	lg	%r0,16(%r1)
	tmhh	%r0,16384
	jz	.Ldone
	larl	%r4,poly1305_blocks_vx
	larl	%r5,poly1305_emit_vx
	stm	%r6,%r13,6*4(%r15)
	stm	%r4,%r5,4*0+228(%r2)
	lg	%r9,32(%r2)
	lg	%r11,40(%r2)
	lghi	%r13,0
	lgr	%r6,%r9
	lr	%r1,%r6
	nilh	%r1,1023
	lgr	%r7,%r11
	lr	%r4,%r1
	srlg	%r1,%r6,52
	lgr	%r8,%r13
	srlg	%r0,%r6,26
	sll	%r8,24
	lr	%r6,%r7
	nilh	%r0,1023
	sll	%r6,12
	lr	%r5,%r0
	or	%r6,%r1
	srlg	%r1,%r7,40
	nilh	%r6,1023
	or	%r8,%r1
	srlg	%r7,%r7,14
	nilh	%r8,1023
	nilh	%r7,1023
	stm	%r4,%r8,48(%r2)
	mhi	%r4,5
	mhi	%r5,5
	mhi	%r6,5
	mhi	%r7,5
	mhi	%r8,5
	stm	%r4,%r8,68(%r2)
	lg	%r0,32(%r2)
	lg	%r1,40(%r2)
	srlg	%r12,%r1,2
	algr	%r12,%r1
	lgr	%r5,%r9
	lgr	%r7,%r11
	mlgr	%r4,%r0
	lgr	%r11,%r7
	mlgr	%r6,%r12
	mlgr	%r8,%r1
	mlgr	%r10,%r0
	algr	%r5,%r7
	lgr	%r7,%r13
	alcgr	%r4,%r6
	lghi	%r6,0
	algr	%r11,%r9
	alcgr	%r10,%r8
	msgr	%r7,%r12
	msgr	%r13,%r0
	algr	%r11,%r7
	alcgr	%r10,%r6
	algr	%r11,%r4
	alcgr	%r13,%r10
	lghi	%r9,-4
	ngr	%r9,%r13
	srlg	%r8,%r13,2
	algr	%r9,%r8
	lghi	%r10,3
	ngr	%r13,%r10
	algr	%r9,%r5
	alcgr	%r11,%r6
	alcgr	%r13,%r6
	lgr	%r6,%r9
	lr	%r1,%r6
	nilh	%r1,1023
	lgr	%r7,%r11
	lr	%r4,%r1
	srlg	%r1,%r6,52
	lgr	%r8,%r13
	srlg	%r0,%r6,26
	sll	%r8,24
	lr	%r6,%r7
	nilh	%r0,1023
	sll	%r6,12
	lr	%r5,%r0
	or	%r6,%r1
	srlg	%r1,%r7,40
	nilh	%r6,1023
	or	%r8,%r1
	srlg	%r7,%r7,14
	nilh	%r8,1023
	nilh	%r7,1023
	stm	%r4,%r8,88(%r2)
	mhi	%r4,5
	mhi	%r5,5
	mhi	%r6,5
	mhi	%r7,5
	mhi	%r8,5
	stm	%r4,%r8,108(%r2)
	lg	%r0,32(%r2)
	lg	%r1,40(%r2)
	srlg	%r12,%r1,2
	algr	%r12,%r1
	lgr	%r5,%r9
	lgr	%r7,%r11
	mlgr	%r4,%r0
	lgr	%r11,%r7
	mlgr	%r6,%r12
	mlgr	%r8,%r1
	mlgr	%r10,%r0
	algr	%r5,%r7
	lgr	%r7,%r13
	alcgr	%r4,%r6
	lghi	%r6,0
	algr	%r11,%r9
	alcgr	%r10,%r8
	msgr	%r7,%r12
	msgr	%r13,%r0
	algr	%r11,%r7
	alcgr	%r10,%r6
	algr	%r11,%r4
	alcgr	%r13,%r10
	lghi	%r9,-4
	ngr	%r9,%r13
	srlg	%r8,%r13,2
	algr	%r9,%r8
	lghi	%r10,3
	ngr	%r13,%r10
	algr	%r9,%r5
	alcgr	%r11,%r6
	alcgr	%r13,%r6
	lg	%r0,32(%r2)
	lg	%r1,40(%r2)
	srlg	%r12,%r1,2
	algr	%r12,%r1
	lgr	%r5,%r9
	lgr	%r7,%r11
	mlgr	%r4,%r0
	lgr	%r11,%r7
	mlgr	%r6,%r12
	mlgr	%r8,%r1
	mlgr	%r10,%r0
	algr	%r5,%r7
	lgr	%r7,%r13
	alcgr	%r4,%r6
	lghi	%r6,0
	algr	%r11,%r9
	alcgr	%r10,%r8
	msgr	%r7,%r12
	msgr	%r13,%r0
	algr	%r11,%r7
	alcgr	%r10,%r6
	algr	%r11,%r4
	alcgr	%r13,%r10
	lghi	%r9,-4
	ngr	%r9,%r13
	srlg	%r8,%r13,2
	algr	%r9,%r8
	lghi	%r10,3
	ngr	%r13,%r10
	algr	%r9,%r5
	alcgr	%r11,%r6
	alcgr	%r13,%r6
	lgr	%r6,%r9
	lr	%r1,%r6
	nilh	%r1,1023
	lgr	%r7,%r11
	lr	%r4,%r1
	srlg	%r1,%r6,52
	lgr	%r8,%r13
	srlg	%r0,%r6,26
	sll	%r8,24
	lr	%r6,%r7
	nilh	%r0,1023
	sll	%r6,12
	lr	%r5,%r0
	or	%r6,%r1
	srlg	%r1,%r7,40
	nilh	%r6,1023
	or	%r8,%r1
	srlg	%r7,%r7,14
	nilh	%r8,1023
	nilh	%r7,1023
	stm	%r4,%r8,128(%r2)
	mhi	%r4,5
	mhi	%r5,5
	mhi	%r6,5
	mhi	%r7,5
	mhi	%r8,5
	stm	%r4,%r8,148(%r2)
	lghi	%r0,0
	stg	%r0,24(%r2)
	stg	%r0,32(%r2)
	stg	%r0,40(%r2)
	lm	%r6,%r13,6*4(%r15)
	lghi	%r2,1
	br	%r14
.Ldone:
	lghi	%r2,0
	br	%r14
.SIZE	poly1305_init,.-poly1305_init
.GLOBL	poly1305_blocks_vx
.TYPE	poly1305_blocks_vx,@function
.ALIGN	16
poly1305_blocks_vx:
	std	%f4,16*4+2*8(%r15)
	std	%f6,16*4+3*8(%r15)
	llgfr	%r4,%r4
	llgfr	%r0,%r5
	.word	0xe7a0,0x2000,0x1003	# vlef	%v10,4*0(%r2),1
	.word	0xe7b0,0x2004,0x1003	# vlef	%v11,4*1(%r2),1
	.word	0xe7c0,0x2008,0x1003	# vlef	%v12,4*2(%r2),1
	.word	0xe7d0,0x200c,0x1003	# vlef	%v13,4*3(%r2),1
	.word	0xe7e0,0x2010,0x1003	# vlef	%v14,4*4(%r2),1
	larl	%r5,.Lconst
	.word	0xe7a0,0x2018,0x3003	# vlef	%v10,24+4*0(%r2),3
	.word	0xe7b0,0x201c,0x3003	# vlef	%v11,24+4*1(%r2),3
	.word	0xe7c0,0x2020,0x3003	# vlef	%v12,24+4*2(%r2),3
	.word	0xe7d0,0x2024,0x3003	# vlef	%v13,24+4*3(%r2),3
	.word	0xe7e0,0x2028,0x3003	# vlef	%v14,24+4*4(%r2),3
	sllg	%r0,%r0,24
	.word	0xe7cf,0x5000,0x0c36	# vlm	%v28,%v31,0(%r5)
	.word	0xe7b0,0x0707,0x0844	# vgbm	%v27,1799
	.word	0xe7a0,000000,0x0862	# vlvgp	%v26,%r0,%r0
	srlg	%r1,%r4,6
	ltgr	%r1,%r1
	jz	.Lvx_4x_done
.ALIGN	16
.Lvx_4x:
	.word	0xe747,0x3000,0x0c36	# vlm	%v20,%v23,0(%r3)
	.word	0xe704,0x5000,0xc78c	# vperm	%v0,%v20,%v21,%v28
	.word	0xe756,0x7000,0xc78c	# vperm	%v5,%v22,%v23,%v28
	.word	0xe724,0x5000,0xd78c	# vperm	%v2,%v20,%v21,%v29
	.word	0xe776,0x7000,0xd78c	# vperm	%v7,%v22,%v23,%v29
	.word	0xe744,0x5000,0xe78c	# vperm	%v4,%v20,%v21,%v30
	.word	0xe796,0x7000,0xe78c	# vperm	%v9,%v22,%v23,%v30
	.word	0xe710,0x001a,0x3038	# vesrl	%v1,%v0,26,3
	.word	0xe765,0x001a,0x3038	# vesrl	%v6,%v5,26,3
	.word	0xe732,0x001e,0x3038	# vesrl	%v3,%v2,30,3
	.word	0xe787,0x001e,0x3038	# vesrl	%v8,%v7,30,3
	.word	0xe722,0x0004,0x3038	# vesrl	%v2,%v2,4,3
	.word	0xe777,0x0004,0x3038	# vesrl	%v7,%v7,4,3
	.word	0xe744,0xb000,0x0268	# vn	%v4,%v4,%v27
	.word	0xe799,0xb000,0x0268	# vn	%v9,%v9,%v27
	.word	0xe700,0xf000,0x0268	# vn	%v0,%v0,%v31
	.word	0xe755,0xf000,0x0268	# vn	%v5,%v5,%v31
	.word	0xe711,0xf000,0x0268	# vn	%v1,%v1,%v31
	.word	0xe766,0xf000,0x0268	# vn	%v6,%v6,%v31
	.word	0xe722,0xf000,0x0268	# vn	%v2,%v2,%v31
	.word	0xe777,0xf000,0x0268	# vn	%v7,%v7,%v31
	.word	0xe733,0xf000,0x0268	# vn	%v3,%v3,%v31
	.word	0xe788,0xf000,0x0268	# vn	%v8,%v8,%v31
	.word	0xe744,0xa000,0x22f3	# va	%v4,%v4,%v26,2
	.word	0xe799,0xa000,0x22f3	# va	%v9,%v9,%v26,2
	.word	0xe740,0x206c,0x2805	# vlrep	%v20,4*0+108(%r2),2
	.word	0xe750,0x2070,0x2805	# vlrep	%v21,4*1+108(%r2),2
	.word	0xe760,0x2074,0x2805	# vlrep	%v22,4*2+108(%r2),2
	.word	0xe770,0x2078,0x2805	# vlrep	%v23,4*3+108(%r2),2
	.word	0xe780,0x207c,0x2805	# vlrep	%v24,4*4+108(%r2),2
	.word	0xe7f0,0x2058,0x2005	# vlrep	%v15,4*0+88(%r2),2
	.word	0xe700,0x205c,0x2805	# vlrep	%v16,4*1+88(%r2),2
	.word	0xe710,0x2060,0x2805	# vlrep	%v17,4*2+88(%r2),2
	.word	0xe720,0x2064,0x2805	# vlrep	%v18,4*3+88(%r2),2
	.word	0xe730,0x2068,0x2805	# vlrep	%v19,4*4+88(%r2),2
	.word	0xe754,0x5200,0x52ad	# vmalo	%v5,%v4,%v21,%v5,2
	.word	0xe764,0x6200,0x62ad	# vmalo	%v6,%v4,%v22,%v6,2
	.word	0xe774,0x7200,0x72ad	# vmalo	%v7,%v4,%v23,%v7,2
	.word	0xe784,0x8200,0x82ad	# vmalo	%v8,%v4,%v24,%v8,2
	.word	0xe794,0xf200,0x90ad	# vmalo	%v9,%v4,%v15,%v9,2
	.word	0xe753,0x6200,0x52ad	# vmalo	%v5,%v3,%v22,%v5,2
	.word	0xe763,0x7200,0x62ad	# vmalo	%v6,%v3,%v23,%v6,2
	.word	0xe773,0x8200,0x72ad	# vmalo	%v7,%v3,%v24,%v7,2
	.word	0xe783,0xf200,0x80ad	# vmalo	%v8,%v3,%v15,%v8,2
	.word	0xe793,0x0200,0x92ad	# vmalo	%v9,%v3,%v16,%v9,2
	.word	0xe752,0x7200,0x52ad	# vmalo	%v5,%v2,%v23,%v5,2
	.word	0xe762,0x8200,0x62ad	# vmalo	%v6,%v2,%v24,%v6,2
	.word	0xe772,0xf200,0x70ad	# vmalo	%v7,%v2,%v15,%v7,2
	.word	0xe782,0x0200,0x82ad	# vmalo	%v8,%v2,%v16,%v8,2
	.word	0xe792,0x1200,0x92ad	# vmalo	%v9,%v2,%v17,%v9,2
	.word	0xe751,0x8200,0x52ad	# vmalo	%v5,%v1,%v24,%v5,2
	.word	0xe761,0xf200,0x60ad	# vmalo	%v6,%v1,%v15,%v6,2
	.word	0xe771,0x0200,0x72ad	# vmalo	%v7,%v1,%v16,%v7,2
	.word	0xe781,0x1200,0x82ad	# vmalo	%v8,%v1,%v17,%v8,2
	.word	0xe791,0x2200,0x92ad	# vmalo	%v9,%v1,%v18,%v9,2
	.word	0xe750,0xf200,0x50ad	# vmalo	%v5,%v0,%v15,%v5,2
	.word	0xe760,0x0200,0x62ad	# vmalo	%v6,%v0,%v16,%v6,2
	.word	0xe770,0x1200,0x72ad	# vmalo	%v7,%v0,%v17,%v7,2
	.word	0xe780,0x2200,0x82ad	# vmalo	%v8,%v0,%v18,%v8,2
	.word	0xe790,0x3200,0x92ad	# vmalo	%v9,%v0,%v19,%v9,2
	.word	0xe740,0x2094,0x2805	# vlrep	%v20,4*0+148(%r2),2
	.word	0xe750,0x2098,0x2805	# vlrep	%v21,4*1+148(%r2),2
	.word	0xe760,0x209c,0x2805	# vlrep	%v22,4*2+148(%r2),2
	.word	0xe770,0x20a0,0x2805	# vlrep	%v23,4*3+148(%r2),2
	.word	0xe780,0x20a4,0x2805	# vlrep	%v24,4*4+148(%r2),2
	.word	0xe7f0,0x2080,0x2005	# vlrep	%v15,4*0+128(%r2),2
	.word	0xe700,0x2084,0x2805	# vlrep	%v16,4*1+128(%r2),2
	.word	0xe710,0x2088,0x2805	# vlrep	%v17,4*2+128(%r2),2
	.word	0xe720,0x208c,0x2805	# vlrep	%v18,4*3+128(%r2),2
	.word	0xe730,0x2090,0x2805	# vlrep	%v19,4*4+128(%r2),2
	.word	0xe75e,0x5200,0x52ad	# vmalo	%v5,%v14,%v21,%v5,2
	.word	0xe76e,0x6200,0x62ad	# vmalo	%v6,%v14,%v22,%v6,2
	.word	0xe77e,0x7200,0x72ad	# vmalo	%v7,%v14,%v23,%v7,2
	.word	0xe78e,0x8200,0x82ad	# vmalo	%v8,%v14,%v24,%v8,2
	.word	0xe79e,0xf200,0x90ad	# vmalo	%v9,%v14,%v15,%v9,2
	.word	0xe75d,0x6200,0x52ad	# vmalo	%v5,%v13,%v22,%v5,2
	.word	0xe76d,0x7200,0x62ad	# vmalo	%v6,%v13,%v23,%v6,2
	.word	0xe77d,0x8200,0x72ad	# vmalo	%v7,%v13,%v24,%v7,2
	.word	0xe78d,0xf200,0x80ad	# vmalo	%v8,%v13,%v15,%v8,2
	.word	0xe79d,0x0200,0x92ad	# vmalo	%v9,%v13,%v16,%v9,2
	.word	0xe75c,0x7200,0x52ad	# vmalo	%v5,%v12,%v23,%v5,2
	.word	0xe76c,0x8200,0x62ad	# vmalo	%v6,%v12,%v24,%v6,2
	.word	0xe77c,0xf200,0x70ad	# vmalo	%v7,%v12,%v15,%v7,2
	.word	0xe78c,0x0200,0x82ad	# vmalo	%v8,%v12,%v16,%v8,2
	.word	0xe79c,0x1200,0x92ad	# vmalo	%v9,%v12,%v17,%v9,2
	.word	0xe75b,0x8200,0x52ad	# vmalo	%v5,%v11,%v24,%v5,2
	.word	0xe76b,0xf200,0x60ad	# vmalo	%v6,%v11,%v15,%v6,2
	.word	0xe77b,0x0200,0x72ad	# vmalo	%v7,%v11,%v16,%v7,2
	.word	0xe78b,0x1200,0x82ad	# vmalo	%v8,%v11,%v17,%v8,2
	.word	0xe79b,0x2200,0x92ad	# vmalo	%v9,%v11,%v18,%v9,2
	.word	0xe7ba,0x0200,0x62ad	# vmalo	%v11,%v10,%v16,%v6,2
	.word	0xe7ca,0x1200,0x72ad	# vmalo	%v12,%v10,%v17,%v7,2
	.word	0xe7da,0x2200,0x82ad	# vmalo	%v13,%v10,%v18,%v8,2
	.word	0xe7ea,0x3200,0x92ad	# vmalo	%v14,%v10,%v19,%v9,2
	.word	0xe7aa,0xf200,0x50ad	# vmalo	%v10,%v10,%v15,%v5,2
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	.word	0xe76b,0x001a,0x3038	# vesrl	%v6,%v11,26,3
	.word	0xe79e,0x001a,0x3038	# vesrl	%v9,%v14,26,3
	.word	0xe7bb,0xf000,0x0268	# vn	%v11,%v11,%v31
	.word	0xe7ee,0xf000,0x0268	# vn	%v14,%v14,%v31
	.word	0xe759,0x0002,0x3030	# vesl	%v5,%v9,2,3
	.word	0xe799,0x5000,0x30f3	# va	%v9,%v9,%v5,3
	.word	0xe7cc,0x6000,0x30f3	# va	%v12,%v12,%v6,3
	.word	0xe7aa,0x9000,0x30f3	# va	%v10,%v10,%v9,3
	.word	0xe77c,0x001a,0x3038	# vesrl	%v7,%v12,26,3
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe7cc,0xf000,0x0268	# vn	%v12,%v12,%v31
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0x7000,0x30f3	# va	%v13,%v13,%v7,3
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	la	%r3,64(%r3)
	brctg	%r1,.Lvx_4x
.ALIGN	16
.Lvx_4x_done:
	tml	%r4,32
	jz	.Lvx_2x_done
	.word	0xe745,0x3000,0x0c36	# vlm	%v20,%v21,0(%r3)
	.word	0xe704,0x5000,0xc78c	# vperm	%v0,%v20,%v21,%v28
	.word	0xe724,0x5000,0xd78c	# vperm	%v2,%v20,%v21,%v29
	.word	0xe744,0x5000,0xe78c	# vperm	%v4,%v20,%v21,%v30
	.word	0xe710,0x001a,0x3038	# vesrl	%v1,%v0,26,3
	.word	0xe732,0x001e,0x3038	# vesrl	%v3,%v2,30,3
	.word	0xe722,0x0004,0x3038	# vesrl	%v2,%v2,4,3
	.word	0xe744,0xb000,0x0268	# vn	%v4,%v4,%v27
	.word	0xe700,0xf000,0x0268	# vn	%v0,%v0,%v31
	.word	0xe711,0xf000,0x0268	# vn	%v1,%v1,%v31
	.word	0xe722,0xf000,0x0268	# vn	%v2,%v2,%v31
	.word	0xe733,0xf000,0x0268	# vn	%v3,%v3,%v31
	.word	0xe744,0xa000,0x22f3	# va	%v4,%v4,%v26,2
	.word	0xe740,0x206c,0x2805	# vlrep	%v20,4*0+108(%r2),2
	.word	0xe750,0x2070,0x2805	# vlrep	%v21,4*1+108(%r2),2
	.word	0xe760,0x2074,0x2805	# vlrep	%v22,4*2+108(%r2),2
	.word	0xe770,0x2078,0x2805	# vlrep	%v23,4*3+108(%r2),2
	.word	0xe780,0x207c,0x2805	# vlrep	%v24,4*4+108(%r2),2
	.word	0xe7f0,0x2058,0x2005	# vlrep	%v15,4*0+88(%r2),2
	.word	0xe700,0x205c,0x2805	# vlrep	%v16,4*1+88(%r2),2
	.word	0xe710,0x2060,0x2805	# vlrep	%v17,4*2+88(%r2),2
	.word	0xe720,0x2064,0x2805	# vlrep	%v18,4*3+88(%r2),2
	.word	0xe730,0x2068,0x2805	# vlrep	%v19,4*4+88(%r2),2
	.word	0xe75e,0x5200,0x02ad	# vmalo	%v5,%v14,%v21,%v0,2
	.word	0xe76e,0x6200,0x12ad	# vmalo	%v6,%v14,%v22,%v1,2
	.word	0xe77e,0x7200,0x22ad	# vmalo	%v7,%v14,%v23,%v2,2
	.word	0xe78e,0x8200,0x32ad	# vmalo	%v8,%v14,%v24,%v3,2
	.word	0xe79e,0xf200,0x40ad	# vmalo	%v9,%v14,%v15,%v4,2
	.word	0xe75d,0x6200,0x52ad	# vmalo	%v5,%v13,%v22,%v5,2
	.word	0xe76d,0x7200,0x62ad	# vmalo	%v6,%v13,%v23,%v6,2
	.word	0xe77d,0x8200,0x72ad	# vmalo	%v7,%v13,%v24,%v7,2
	.word	0xe78d,0xf200,0x80ad	# vmalo	%v8,%v13,%v15,%v8,2
	.word	0xe79d,0x0200,0x92ad	# vmalo	%v9,%v13,%v16,%v9,2
	.word	0xe75c,0x7200,0x52ad	# vmalo	%v5,%v12,%v23,%v5,2
	.word	0xe76c,0x8200,0x62ad	# vmalo	%v6,%v12,%v24,%v6,2
	.word	0xe77c,0xf200,0x70ad	# vmalo	%v7,%v12,%v15,%v7,2
	.word	0xe78c,0x0200,0x82ad	# vmalo	%v8,%v12,%v16,%v8,2
	.word	0xe79c,0x1200,0x92ad	# vmalo	%v9,%v12,%v17,%v9,2
	.word	0xe75b,0x8200,0x52ad	# vmalo	%v5,%v11,%v24,%v5,2
	.word	0xe76b,0xf200,0x60ad	# vmalo	%v6,%v11,%v15,%v6,2
	.word	0xe77b,0x0200,0x72ad	# vmalo	%v7,%v11,%v16,%v7,2
	.word	0xe78b,0x1200,0x82ad	# vmalo	%v8,%v11,%v17,%v8,2
	.word	0xe79b,0x2200,0x92ad	# vmalo	%v9,%v11,%v18,%v9,2
	.word	0xe7ba,0x0200,0x62ad	# vmalo	%v11,%v10,%v16,%v6,2
	.word	0xe7ca,0x1200,0x72ad	# vmalo	%v12,%v10,%v17,%v7,2
	.word	0xe7da,0x2200,0x82ad	# vmalo	%v13,%v10,%v18,%v8,2
	.word	0xe7ea,0x3200,0x92ad	# vmalo	%v14,%v10,%v19,%v9,2
	.word	0xe7aa,0xf200,0x50ad	# vmalo	%v10,%v10,%v15,%v5,2
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	.word	0xe76b,0x001a,0x3038	# vesrl	%v6,%v11,26,3
	.word	0xe79e,0x001a,0x3038	# vesrl	%v9,%v14,26,3
	.word	0xe7bb,0xf000,0x0268	# vn	%v11,%v11,%v31
	.word	0xe7ee,0xf000,0x0268	# vn	%v14,%v14,%v31
	.word	0xe759,0x0002,0x3030	# vesl	%v5,%v9,2,3
	.word	0xe799,0x5000,0x30f3	# va	%v9,%v9,%v5,3
	.word	0xe7cc,0x6000,0x30f3	# va	%v12,%v12,%v6,3
	.word	0xe7aa,0x9000,0x30f3	# va	%v10,%v10,%v9,3
	.word	0xe77c,0x001a,0x3038	# vesrl	%v7,%v12,26,3
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe7cc,0xf000,0x0268	# vn	%v12,%v12,%v31
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0x7000,0x30f3	# va	%v13,%v13,%v7,3
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	la	%r3,32(%r3)
.ALIGN	16
.Lvx_2x_done:
	tml	%r4,16
	jz	.Lvx_done
	.word	0xe7a0,000000,0x0842	# vleig	%v26,0,0
	.word	0xe740,000000,0x0844	# vgbm	%v20,0
	.word	0xe750,0x3000,0x0806	# vl	%v21,0(%r3)
	.word	0xe704,0x5000,0xc78c	# vperm	%v0,%v20,%v21,%v28
	.word	0xe724,0x5000,0xd78c	# vperm	%v2,%v20,%v21,%v29
	.word	0xe744,0x5000,0xe78c	# vperm	%v4,%v20,%v21,%v30
	.word	0xe710,0x001a,0x3038	# vesrl	%v1,%v0,26,3
	.word	0xe732,0x001e,0x3038	# vesrl	%v3,%v2,30,3
	.word	0xe722,0x0004,0x3038	# vesrl	%v2,%v2,4,3
	.word	0xe744,0xb000,0x0268	# vn	%v4,%v4,%v27
	.word	0xe700,0xf000,0x0268	# vn	%v0,%v0,%v31
	.word	0xe711,0xf000,0x0268	# vn	%v1,%v1,%v31
	.word	0xe722,0xf000,0x0268	# vn	%v2,%v2,%v31
	.word	0xe733,0xf000,0x0268	# vn	%v3,%v3,%v31
	.word	0xe744,0xa000,0x22f3	# va	%v4,%v4,%v26,2
	.word	0xe740,0x2044,0x2805	# vlrep	%v20,4*0+68(%r2),2
	.word	0xe750,0x2048,0x2805	# vlrep	%v21,4*1+68(%r2),2
	.word	0xe760,0x204c,0x2805	# vlrep	%v22,4*2+68(%r2),2
	.word	0xe770,0x2050,0x2805	# vlrep	%v23,4*3+68(%r2),2
	.word	0xe780,0x2054,0x2805	# vlrep	%v24,4*4+68(%r2),2
	.word	0xe7f0,0x2030,0x2005	# vlrep	%v15,4*0+48(%r2),2
	.word	0xe700,0x2034,0x2805	# vlrep	%v16,4*1+48(%r2),2
	.word	0xe710,0x2038,0x2805	# vlrep	%v17,4*2+48(%r2),2
	.word	0xe720,0x203c,0x2805	# vlrep	%v18,4*3+48(%r2),2
	.word	0xe730,0x2040,0x2805	# vlrep	%v19,4*4+48(%r2),2
	.word	0xe75e,0x5200,0x02ad	# vmalo	%v5,%v14,%v21,%v0,2
	.word	0xe76e,0x6200,0x12ad	# vmalo	%v6,%v14,%v22,%v1,2
	.word	0xe77e,0x7200,0x22ad	# vmalo	%v7,%v14,%v23,%v2,2
	.word	0xe78e,0x8200,0x32ad	# vmalo	%v8,%v14,%v24,%v3,2
	.word	0xe79e,0xf200,0x40ad	# vmalo	%v9,%v14,%v15,%v4,2
	.word	0xe75d,0x6200,0x52ad	# vmalo	%v5,%v13,%v22,%v5,2
	.word	0xe76d,0x7200,0x62ad	# vmalo	%v6,%v13,%v23,%v6,2
	.word	0xe77d,0x8200,0x72ad	# vmalo	%v7,%v13,%v24,%v7,2
	.word	0xe78d,0xf200,0x80ad	# vmalo	%v8,%v13,%v15,%v8,2
	.word	0xe79d,0x0200,0x92ad	# vmalo	%v9,%v13,%v16,%v9,2
	.word	0xe75c,0x7200,0x52ad	# vmalo	%v5,%v12,%v23,%v5,2
	.word	0xe76c,0x8200,0x62ad	# vmalo	%v6,%v12,%v24,%v6,2
	.word	0xe77c,0xf200,0x70ad	# vmalo	%v7,%v12,%v15,%v7,2
	.word	0xe78c,0x0200,0x82ad	# vmalo	%v8,%v12,%v16,%v8,2
	.word	0xe79c,0x1200,0x92ad	# vmalo	%v9,%v12,%v17,%v9,2
	.word	0xe75b,0x8200,0x52ad	# vmalo	%v5,%v11,%v24,%v5,2
	.word	0xe76b,0xf200,0x60ad	# vmalo	%v6,%v11,%v15,%v6,2
	.word	0xe77b,0x0200,0x72ad	# vmalo	%v7,%v11,%v16,%v7,2
	.word	0xe78b,0x1200,0x82ad	# vmalo	%v8,%v11,%v17,%v8,2
	.word	0xe79b,0x2200,0x92ad	# vmalo	%v9,%v11,%v18,%v9,2
	.word	0xe7ba,0x0200,0x62ad	# vmalo	%v11,%v10,%v16,%v6,2
	.word	0xe7ca,0x1200,0x72ad	# vmalo	%v12,%v10,%v17,%v7,2
	.word	0xe7da,0x2200,0x82ad	# vmalo	%v13,%v10,%v18,%v8,2
	.word	0xe7ea,0x3200,0x92ad	# vmalo	%v14,%v10,%v19,%v9,2
	.word	0xe7aa,0xf200,0x50ad	# vmalo	%v10,%v10,%v15,%v5,2
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	.word	0xe76b,0x001a,0x3038	# vesrl	%v6,%v11,26,3
	.word	0xe79e,0x001a,0x3038	# vesrl	%v9,%v14,26,3
	.word	0xe7bb,0xf000,0x0268	# vn	%v11,%v11,%v31
	.word	0xe7ee,0xf000,0x0268	# vn	%v14,%v14,%v31
	.word	0xe759,0x0002,0x3030	# vesl	%v5,%v9,2,3
	.word	0xe799,0x5000,0x30f3	# va	%v9,%v9,%v5,3
	.word	0xe7cc,0x6000,0x30f3	# va	%v12,%v12,%v6,3
	.word	0xe7aa,0x9000,0x30f3	# va	%v10,%v10,%v9,3
	.word	0xe77c,0x001a,0x3038	# vesrl	%v7,%v12,26,3
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe7cc,0xf000,0x0268	# vn	%v12,%v12,%v31
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0x7000,0x30f3	# va	%v13,%v13,%v7,3
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
.ALIGN	16
.Lvx_done:
	.word	0xe7a0,0x2000,0x100b	# vstef	%v10,4*0(%r2),1
	.word	0xe7b0,0x2004,0x100b	# vstef	%v11,4*1(%r2),1
	.word	0xe7c0,0x2008,0x100b	# vstef	%v12,4*2(%r2),1
	.word	0xe7d0,0x200c,0x100b	# vstef	%v13,4*3(%r2),1
	.word	0xe7e0,0x2010,0x100b	# vstef	%v14,4*4(%r2),1
	.word	0xe7a0,0x2018,0x300b	# vstef	%v10,24+4*0(%r2),3
	.word	0xe7b0,0x201c,0x300b	# vstef	%v11,24+4*1(%r2),3
	.word	0xe7c0,0x2020,0x300b	# vstef	%v12,24+4*2(%r2),3
	.word	0xe7d0,0x2024,0x300b	# vstef	%v13,24+4*3(%r2),3
	.word	0xe7e0,0x2028,0x300b	# vstef	%v14,24+4*4(%r2),3
	ld	%f4,16*4+2*8(%r15)
	ld	%f6,16*4+3*8(%r15)
	br	%r14
.SIZE	poly1305_blocks_vx,.-poly1305_blocks_vx
.GLOBL	poly1305_emit_vx
.TYPE	poly1305_emit_vx,@function
.ALIGN	16
poly1305_emit_vx:
	std	%f4,16*4+2*8(%r15)
	std	%f6,16*4+3*8(%r15)
	larl	%r5,.Lconst
	.word	0xe7a0,0x2000,0x1003	# vlef	%v10,4*0(%r2),1
	.word	0xe7b0,0x2004,0x1003	# vlef	%v11,4*1(%r2),1
	.word	0xe7c0,0x2008,0x1003	# vlef	%v12,4*2(%r2),1
	.word	0xe7d0,0x200c,0x1003	# vlef	%v13,4*3(%r2),1
	.word	0xe7e0,0x2010,0x1003	# vlef	%v14,4*4(%r2),1
	.word	0xe7a0,0x2018,0x3003	# vlef	%v10,24+4*0(%r2),3
	.word	0xe7b0,0x201c,0x3003	# vlef	%v11,24+4*1(%r2),3
	.word	0xe7c0,0x2020,0x3003	# vlef	%v12,24+4*2(%r2),3
	.word	0xe7d0,0x2024,0x3003	# vlef	%v13,24+4*3(%r2),3
	.word	0xe7e0,0x2028,0x3003	# vlef	%v14,24+4*4(%r2),3
	.word	0xe740,0x206c,0x1803	# vlef	%v20,108+4*0(%r2),1
	.word	0xe750,0x2070,0x1803	# vlef	%v21,108+4*1(%r2),1
	.word	0xe760,0x2074,0x1803	# vlef	%v22,108+4*2(%r2),1
	.word	0xe770,0x2078,0x1803	# vlef	%v23,108+4*3(%r2),1
	.word	0xe780,0x207c,0x1803	# vlef	%v24,108+4*4(%r2),1
	.word	0xe7f0,0x2058,0x1003	# vlef	%v15,88+4*0(%r2),1
	.word	0xe700,0x205c,0x1803	# vlef	%v16,88+4*1(%r2),1
	.word	0xe710,0x2060,0x1803	# vlef	%v17,88+4*2(%r2),1
	.word	0xe720,0x2064,0x1803	# vlef	%v18,88+4*3(%r2),1
	.word	0xe730,0x2068,0x1803	# vlef	%v19,88+4*4(%r2),1
	.word	0xe740,0x2044,0x3803	# vlef	%v20,68+4*0(%r2),3
	.word	0xe750,0x2048,0x3803	# vlef	%v21,68+4*1(%r2),3
	.word	0xe760,0x204c,0x3803	# vlef	%v22,68+4*2(%r2),3
	.word	0xe770,0x2050,0x3803	# vlef	%v23,68+4*3(%r2),3
	.word	0xe780,0x2054,0x3803	# vlef	%v24,68+4*4(%r2),3
	.word	0xe7f0,0x2030,0x3003	# vlef	%v15,48+4*0(%r2),3
	.word	0xe700,0x2034,0x3803	# vlef	%v16,48+4*1(%r2),3
	.word	0xe710,0x2038,0x3803	# vlef	%v17,48+4*2(%r2),3
	.word	0xe720,0x203c,0x3803	# vlef	%v18,48+4*3(%r2),3
	.word	0xe730,0x2040,0x3803	# vlef	%v19,48+4*4(%r2),3
	.word	0xe7f0,0x5030,0x0806	# vl	%v31,48(%r5)
	.word	0xe75e,0x5000,0x22a5	# vmlo	%v5,%v14,%v21,2
	.word	0xe76e,0x6000,0x22a5	# vmlo	%v6,%v14,%v22,2
	.word	0xe77e,0x7000,0x22a5	# vmlo	%v7,%v14,%v23,2
	.word	0xe78e,0x8000,0x22a5	# vmlo	%v8,%v14,%v24,2
	.word	0xe79e,0xf000,0x20a5	# vmlo	%v9,%v14,%v15,2
	.word	0xe75d,0x6200,0x52ad	# vmalo	%v5,%v13,%v22,%v5,2
	.word	0xe76d,0x7200,0x62ad	# vmalo	%v6,%v13,%v23,%v6,2
	.word	0xe77d,0x8200,0x72ad	# vmalo	%v7,%v13,%v24,%v7,2
	.word	0xe78d,0xf200,0x80ad	# vmalo	%v8,%v13,%v15,%v8,2
	.word	0xe79d,0x0200,0x92ad	# vmalo	%v9,%v13,%v16,%v9,2
	.word	0xe75c,0x7200,0x52ad	# vmalo	%v5,%v12,%v23,%v5,2
	.word	0xe76c,0x8200,0x62ad	# vmalo	%v6,%v12,%v24,%v6,2
	.word	0xe77c,0xf200,0x70ad	# vmalo	%v7,%v12,%v15,%v7,2
	.word	0xe78c,0x0200,0x82ad	# vmalo	%v8,%v12,%v16,%v8,2
	.word	0xe79c,0x1200,0x92ad	# vmalo	%v9,%v12,%v17,%v9,2
	.word	0xe75b,0x8200,0x52ad	# vmalo	%v5,%v11,%v24,%v5,2
	.word	0xe76b,0xf200,0x60ad	# vmalo	%v6,%v11,%v15,%v6,2
	.word	0xe77b,0x0200,0x72ad	# vmalo	%v7,%v11,%v16,%v7,2
	.word	0xe78b,0x1200,0x82ad	# vmalo	%v8,%v11,%v17,%v8,2
	.word	0xe79b,0x2200,0x92ad	# vmalo	%v9,%v11,%v18,%v9,2
	.word	0xe7ba,0x0200,0x62ad	# vmalo	%v11,%v10,%v16,%v6,2
	.word	0xe7ca,0x1200,0x72ad	# vmalo	%v12,%v10,%v17,%v7,2
	.word	0xe7da,0x2200,0x82ad	# vmalo	%v13,%v10,%v18,%v8,2
	.word	0xe7ea,0x3200,0x92ad	# vmalo	%v14,%v10,%v19,%v9,2
	.word	0xe7aa,0xf200,0x50ad	# vmalo	%v10,%v10,%v15,%v5,2
	.word	0xe7b0,000000,0x0844	# vgbm	%v27,0
	.word	0xe7aa,0xb000,0x3267	# vsumq	%v10,%v10,%v27,3
	.word	0xe7bb,0xb000,0x3267	# vsumq	%v11,%v11,%v27,3
	.word	0xe7cc,0xb000,0x3267	# vsumq	%v12,%v12,%v27,3
	.word	0xe7dd,0xb000,0x3267	# vsumq	%v13,%v13,%v27,3
	.word	0xe7ee,0xb000,0x3267	# vsumq	%v14,%v14,%v27,3
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	.word	0xe76b,0x001a,0x3038	# vesrl	%v6,%v11,26,3
	.word	0xe79e,0x001a,0x3038	# vesrl	%v9,%v14,26,3
	.word	0xe7bb,0xf000,0x0268	# vn	%v11,%v11,%v31
	.word	0xe7ee,0xf000,0x0268	# vn	%v14,%v14,%v31
	.word	0xe759,0x0002,0x3030	# vesl	%v5,%v9,2,3
	.word	0xe799,0x5000,0x30f3	# va	%v9,%v9,%v5,3
	.word	0xe7cc,0x6000,0x30f3	# va	%v12,%v12,%v6,3
	.word	0xe7aa,0x9000,0x30f3	# va	%v10,%v10,%v9,3
	.word	0xe77c,0x001a,0x3038	# vesrl	%v7,%v12,26,3
	.word	0xe75a,0x001a,0x3038	# vesrl	%v5,%v10,26,3
	.word	0xe7cc,0xf000,0x0268	# vn	%v12,%v12,%v31
	.word	0xe7aa,0xf000,0x0268	# vn	%v10,%v10,%v31
	.word	0xe7dd,0x7000,0x30f3	# va	%v13,%v13,%v7,3
	.word	0xe7bb,0x5000,0x30f3	# va	%v11,%v11,%v5,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	.word	0xe76b,0x001a,0x3038	# vesrl	%v6,%v11,26,3
	.word	0xe7bb,0xf000,0x0268	# vn	%v11,%v11,%v31
	.word	0xe7cc,0x6000,0x30f3	# va	%v12,%v12,%v6,3
	.word	0xe77c,0x001a,0x3038	# vesrl	%v7,%v12,26,3
	.word	0xe7cc,0xf000,0x0268	# vn	%v12,%v12,%v31
	.word	0xe7dd,0x7000,0x30f3	# va	%v13,%v13,%v7,3
	.word	0xe78d,0x001a,0x3038	# vesrl	%v8,%v13,26,3
	.word	0xe7dd,0xf000,0x0268	# vn	%v13,%v13,%v31
	.word	0xe7ee,0x8000,0x30f3	# va	%v14,%v14,%v8,3
	.word	0xe7e0,0x0030,0x7840	# vleib	%v30,48,7
	.word	0xe7d0,0x0068,0x7840	# vleib	%v29,104,7
	.word	0xe7c0,0x0018,0x7840	# vleib	%v28,24,7
	.word	0xe7bb,0x001a,0x3030	# vesl	%v11,%v11,26,3
	.word	0xe7dd,0x001a,0x3030	# vesl	%v13,%v13,26,3
	.word	0xe7aa,0xb000,0x006a	# vo	%v10,%v10,%v11
	.word	0xe7cc,0xd000,0x006a	# vo	%v12,%v12,%v13
	.word	0xe7cc,0x0004,0x3030	# vesl	%v12,%v12,4,3
	.word	0xe7cc,0xe000,0x0275	# vslb	%v12,%v12,%v30
	.word	0xe7aa,0xc000,0x006a	# vo	%v10,%v10,%v12
	.word	0xe79e,0xd000,0x0275	# vslb	%v9,%v14,%v29
	.word	0xe7aa,0x9000,0x006a	# vo	%v10,%v10,%v9
	.word	0xe7be,0xc000,0x027d	# vsrlb	%v11,%v14,%v28
	.word	0xe7a0,0xffff,0x0844	# vgbm	%v26,65535
	.word	0xe7b0,0x0005,0x1842	# vleig	%v27,5,1
	.word	0xe7d0,0xffff,0x0844	# vgbm	%v29,65535
	.word	0xe7a0,0xfffc,0x1842	# vleig	%v26,-4,1
	.word	0xe75a,0xb000,0x42f3	# va	%v5,%v10,%v27,4
	.word	0xe76a,0xb000,0x42f1	# vacc	%v6,%v10,%v27,4
	.word	0xe766,0xa000,0x42f3	# va	%v6,%v6,%v26,4
	.word	0xe766,0xb000,0x40f1	# vacc	%v6,%v6,%v11,4
	.word	0xe766,0xd000,0x42f3	# va	%v6,%v6,%v29,4
	.word	0xe776,0xa000,0x0068	# vn	%v7,%v6,%v10
	.word	0xe785,0x6000,0x0069	# vnc	%v8,%v5,%v6
	.word	0xe7a7,0x8000,0x006a	# vo	%v10,%v7,%v8
	.word	0xe7c0,0x5040,0x0806	# vl	%v28,64(%r5)
	.word	0xe750,0x4000,0x3003	# vlef	%v5,4*0(%r4),3
	.word	0xe750,0x4004,0x2003	# vlef	%v5,4*1(%r4),2
	.word	0xe750,0x4008,0x1003	# vlef	%v5,4*2(%r4),1
	.word	0xe750,0x400c,0x0003	# vlef	%v5,4*3(%r4),0
	.word	0xe7aa,0x5000,0x40f3	# va	%v10,%v10,%v5,4
	.word	0xe7aa,0xa000,0xc18c	# vperm	%v10,%v10,%v10,%v28
	.word	0xe7a0,0x3000,0x000e	# vst	%v10,0(%r3)
	ld	%f4,16*4+2*8(%r15)
	ld	%f6,16*4+3*8(%r15)
	br	%r14
.SIZE	poly1305_emit_vx,.-poly1305_emit_vx
.GLOBL	poly1305_blocks
.TYPE	poly1305_blocks,@function
.ALIGN	16
poly1305_blocks:
	srl	%r4,4
	lghi	%r0,0
	clr	%r4,%r0
	je	.Lno_data
	stm	%r6,%r14,6*4(%r15)
	llgfr	%r5,%r5
	lg	%r0,32(%r2)
	lg	%r1,40(%r2)
	lg	%r11,0(%r2)
	lg	%r13,8(%r2)
	lg	%r14,16(%r2)
	st	%r2,2*4(%r15)
	srlg	%r2,%r1,2
	algr	%r2,%r1
	j	.Loop
.ALIGN	16
.Loop:
	lrvg	%r7,0(%r3)
	lrvg	%r9,8(%r3)
	la	%r3,16(%r3)
	algr	%r7,%r11
	alcgr	%r9,%r13
	lgr	%r11,%r7
	mlgr	%r6,%r0
	lgr	%r13,%r9
	mlgr	%r8,%r2
	mlgr	%r10,%r1
	mlgr	%r12,%r0
	alcgr	%r14,%r5
	algr	%r7,%r9
	lgr	%r9,%r14
	alcgr	%r6,%r8
	lghi	%r8,0
	algr	%r13,%r11
	alcgr	%r12,%r10
	msgr	%r9,%r2
	msgr	%r14,%r0
	algr	%r13,%r9
	alcgr	%r12,%r8
	algr	%r13,%r6
	alcgr	%r14,%r12
	lghi	%r11,-4
	ngr	%r11,%r14
	srlg	%r10,%r14,2
	algr	%r11,%r10
	lghi	%r12,3
	ngr	%r14,%r12
	algr	%r11,%r7
	alcgr	%r13,%r8
	alcgr	%r14,%r8
	brct	%r4,.Loop
	l	%r2,2*4(%r15)
	stg	%r11,0(%r2)
	stg	%r13,8(%r2)
	stg	%r14,16(%r2)
	lm	%r6,%r14,6*4(%r15)
.Lno_data:
	br	%r14
.SIZE	poly1305_blocks,.-poly1305_blocks
.GLOBL	poly1305_emit
.TYPE	poly1305_emit,@function
.ALIGN	16
poly1305_emit:
	stm	%r6,%r9,6*4(%r15)
	lg	%r5,0(%r2)
	lg	%r6,8(%r2)
	lg	%r7,16(%r2)
	lghi	%r0,5
	lghi	%r1,0
	lgr	%r8,%r5
	lgr	%r9,%r6
	algr	%r5,%r0
	alcgr	%r6,%r1
	alcgr	%r7,%r1
	srlg	%r7,%r7,2
	slgr	%r1,%r7
	lg	%r7,0(%r4)
	lghi	%r0,-1
	lg	%r2,8(%r4)
	xgr	%r0,%r1
	ngr	%r5,%r1
	ngr	%r8,%r0
	ngr	%r6,%r1
	ngr	%r9,%r0
	ogr	%r5,%r8
	rllg	%r8,%r7,32
	ogr	%r6,%r9
	rllg	%r9,%r2,32
	algr	%r5,%r8
	alcgr	%r6,%r9
	strvg	%r5,0(%r3)
	strvg	%r6,8(%r3)
	lm	%r6,%r9,6*4(%r15)
	br	%r14
.SIZE	poly1305_emit,.-poly1305_emit
.ALIGN	128
.Lconst:
.LONG	394500,50462976,1447188,319951120
.LONG	789258,151521030,1841946,421009174
.LONG	0,986637,0,2039325
.LONG	0,67108863,0,67108863
.LONG	252579084,185207048,117835012,50462976
.STRING	"Poly1305 for s390x, CRYPTOGAMS by <appro@openssl.org>"
