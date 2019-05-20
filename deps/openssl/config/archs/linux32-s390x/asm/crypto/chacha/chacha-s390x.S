#include "s390x_arch.h"
.TEXT
.GLOBL	ChaCha20_ctr32
.TYPE	ChaCha20_ctr32,@function
.ALIGN	32
ChaCha20_ctr32:
	larl	%r1,OPENSSL_s390xcap_P
	lghi	%r0,64
	clr	%r4,%r0
	jle	_s390x_chacha_novx
	lg	%r0,S390X_STFLE+16(%r1)
	tmhh	%r0,16384
	jz	_s390x_chacha_novx
	llgfr	%r4,%r4
	std	%f4,16*4+2*8(%r15)
	std	%f6,16*4+3*8(%r15)
	stm	%r6,%r7,6*4(%r15)
	lghi	%r1,-168
	lgr	%r0,%r15
	la	%r15,0(%r1,%r15)
	larl	%r7,.Lsigma
	st	%r0,0(%r15)
	.word	0xe712,0x5000,0x0036	# vlm	%v1,%v2,0(%r5)
	.word	0xe700,0x7000,0x0006	# vl	%v0,0(%r7)
	.word	0xe730,0x6000,0x0006	# vl	%v3,0(%r6)
	l	%r0,0(%r6)
	.word	0xe703,0xf008,0x003e	# vstm	%v0,%v3,8(%r15)
	srlg	%r1,%r4,8
	ltgr	%r1,%r1
	jz	.Lvx_4x_done
.ALIGN	16
.Lvx_4x:
	.word	0xe700,0xf008,0x2005	# vlrep	%v0,0+8(%r15),2
	.word	0xe710,0xf00c,0x2005	# vlrep	%v1,4+8(%r15),2
	.word	0xe720,0xf010,0x2005	# vlrep	%v2,8+8(%r15),2
	.word	0xe730,0xf014,0x2005	# vlrep	%v3,12+8(%r15),2
	.word	0xe740,0xf018,0x2005	# vlrep	%v4,16+8(%r15),2
	.word	0xe750,0xf01c,0x2005	# vlrep	%v5,20+8(%r15),2
	.word	0xe760,0xf020,0x2005	# vlrep	%v6,24+8(%r15),2
	.word	0xe770,0xf024,0x2005	# vlrep	%v7,28+8(%r15),2
	.word	0xe780,0xf028,0x2005	# vlrep	%v8,32+8(%r15),2
	.word	0xe790,0xf02c,0x2005	# vlrep	%v9,36+8(%r15),2
	.word	0xe7a0,0xf030,0x2005	# vlrep	%v10,40+8(%r15),2
	.word	0xe7b0,0xf034,0x2005	# vlrep	%v11,44+8(%r15),2
	.word	0xe7c0,0xf038,0x2005	# vlrep	%v12,48+8(%r15),2
	.word	0xe7d0,0xf03c,0x2005	# vlrep	%v13,52+8(%r15),2
	.word	0xe7e0,0xf040,0x2005	# vlrep	%v14,56+8(%r15),2
	.word	0xe7f0,0xf044,0x2005	# vlrep	%v15,60+8(%r15),2
	.word	0xe7f0,0x7010,0x0806	# vl	%v31,16(%r7)
	.word	0xe7cc,0xf000,0x22f3	# va	%v12,%v12,%v31,2
	.word	0xe700,000000,0x0856	# vlr	%v16,%v0
	.word	0xe711,000000,0x0856	# vlr	%v17,%v1
	.word	0xe722,000000,0x0856	# vlr	%v18,%v2
	.word	0xe733,000000,0x0856	# vlr	%v19,%v3
	.word	0xe744,000000,0x0856	# vlr	%v20,%v4
	.word	0xe755,000000,0x0856	# vlr	%v21,%v5
	.word	0xe766,000000,0x0856	# vlr	%v22,%v6
	.word	0xe777,000000,0x0856	# vlr	%v23,%v7
	.word	0xe788,000000,0x0856	# vlr	%v24,%v8
	.word	0xe799,000000,0x0856	# vlr	%v25,%v9
	.word	0xe7aa,000000,0x0856	# vlr	%v26,%v10
	.word	0xe7bb,000000,0x0856	# vlr	%v27,%v11
	.word	0xe7cc,000000,0x0856	# vlr	%v28,%v12
	.word	0xe7dd,000000,0x0856	# vlr	%v29,%v13
	.word	0xe7ee,000000,0x0856	# vlr	%v30,%v14
	.word	0xe7ff,000000,0x0856	# vlr	%v31,%v15
	lhi	%r6,10
	j	.Loop_vx_4x
.ALIGN	16
.Loop_vx_4x:
	.word	0xe700,0x4000,0x2ef3	# va	%v16,%v16,%v20,2
	.word	0xe711,0x5000,0x2ef3	# va	%v17,%v17,%v21,2
	.word	0xe722,0x6000,0x2ef3	# va	%v18,%v18,%v22,2
	.word	0xe733,0x7000,0x2ef3	# va	%v19,%v19,%v23,2
	.word	0xe7cc,000000,0x0e6d	# vx	%v28,%v28,%v16
	.word	0xe7dd,0x1000,0x0e6d	# vx	%v29,%v29,%v17
	.word	0xe7ee,0x2000,0x0e6d	# vx	%v30,%v30,%v18
	.word	0xe7ff,0x3000,0x0e6d	# vx	%v31,%v31,%v19
	.word	0xe7cc,0x0010,0x2c33	# verll	%v28,%v28,16,2
	.word	0xe7dd,0x0010,0x2c33	# verll	%v29,%v29,16,2
	.word	0xe7ee,0x0010,0x2c33	# verll	%v30,%v30,16,2
	.word	0xe7ff,0x0010,0x2c33	# verll	%v31,%v31,16,2
	.word	0xe788,0xc000,0x2ef3	# va	%v24,%v24,%v28,2
	.word	0xe799,0xd000,0x2ef3	# va	%v25,%v25,%v29,2
	.word	0xe7aa,0xe000,0x2ef3	# va	%v26,%v26,%v30,2
	.word	0xe7bb,0xf000,0x2ef3	# va	%v27,%v27,%v31,2
	.word	0xe744,0x8000,0x0e6d	# vx	%v20,%v20,%v24
	.word	0xe755,0x9000,0x0e6d	# vx	%v21,%v21,%v25
	.word	0xe766,0xa000,0x0e6d	# vx	%v22,%v22,%v26
	.word	0xe777,0xb000,0x0e6d	# vx	%v23,%v23,%v27
	.word	0xe744,0x000c,0x2c33	# verll	%v20,%v20,12,2
	.word	0xe755,0x000c,0x2c33	# verll	%v21,%v21,12,2
	.word	0xe766,0x000c,0x2c33	# verll	%v22,%v22,12,2
	.word	0xe777,0x000c,0x2c33	# verll	%v23,%v23,12,2
	.word	0xe700,0x4000,0x2ef3	# va	%v16,%v16,%v20,2
	.word	0xe711,0x5000,0x2ef3	# va	%v17,%v17,%v21,2
	.word	0xe722,0x6000,0x2ef3	# va	%v18,%v18,%v22,2
	.word	0xe733,0x7000,0x2ef3	# va	%v19,%v19,%v23,2
	.word	0xe7cc,000000,0x0e6d	# vx	%v28,%v28,%v16
	.word	0xe7dd,0x1000,0x0e6d	# vx	%v29,%v29,%v17
	.word	0xe7ee,0x2000,0x0e6d	# vx	%v30,%v30,%v18
	.word	0xe7ff,0x3000,0x0e6d	# vx	%v31,%v31,%v19
	.word	0xe7cc,0x0008,0x2c33	# verll	%v28,%v28,8,2
	.word	0xe7dd,0x0008,0x2c33	# verll	%v29,%v29,8,2
	.word	0xe7ee,0x0008,0x2c33	# verll	%v30,%v30,8,2
	.word	0xe7ff,0x0008,0x2c33	# verll	%v31,%v31,8,2
	.word	0xe788,0xc000,0x2ef3	# va	%v24,%v24,%v28,2
	.word	0xe799,0xd000,0x2ef3	# va	%v25,%v25,%v29,2
	.word	0xe7aa,0xe000,0x2ef3	# va	%v26,%v26,%v30,2
	.word	0xe7bb,0xf000,0x2ef3	# va	%v27,%v27,%v31,2
	.word	0xe744,0x8000,0x0e6d	# vx	%v20,%v20,%v24
	.word	0xe755,0x9000,0x0e6d	# vx	%v21,%v21,%v25
	.word	0xe766,0xa000,0x0e6d	# vx	%v22,%v22,%v26
	.word	0xe777,0xb000,0x0e6d	# vx	%v23,%v23,%v27
	.word	0xe744,0x0007,0x2c33	# verll	%v20,%v20,7,2
	.word	0xe755,0x0007,0x2c33	# verll	%v21,%v21,7,2
	.word	0xe766,0x0007,0x2c33	# verll	%v22,%v22,7,2
	.word	0xe777,0x0007,0x2c33	# verll	%v23,%v23,7,2
	.word	0xe700,0x5000,0x2ef3	# va	%v16,%v16,%v21,2
	.word	0xe711,0x6000,0x2ef3	# va	%v17,%v17,%v22,2
	.word	0xe722,0x7000,0x2ef3	# va	%v18,%v18,%v23,2
	.word	0xe733,0x4000,0x2ef3	# va	%v19,%v19,%v20,2
	.word	0xe7ff,000000,0x0e6d	# vx	%v31,%v31,%v16
	.word	0xe7cc,0x1000,0x0e6d	# vx	%v28,%v28,%v17
	.word	0xe7dd,0x2000,0x0e6d	# vx	%v29,%v29,%v18
	.word	0xe7ee,0x3000,0x0e6d	# vx	%v30,%v30,%v19
	.word	0xe7ff,0x0010,0x2c33	# verll	%v31,%v31,16,2
	.word	0xe7cc,0x0010,0x2c33	# verll	%v28,%v28,16,2
	.word	0xe7dd,0x0010,0x2c33	# verll	%v29,%v29,16,2
	.word	0xe7ee,0x0010,0x2c33	# verll	%v30,%v30,16,2
	.word	0xe7aa,0xf000,0x2ef3	# va	%v26,%v26,%v31,2
	.word	0xe7bb,0xc000,0x2ef3	# va	%v27,%v27,%v28,2
	.word	0xe788,0xd000,0x2ef3	# va	%v24,%v24,%v29,2
	.word	0xe799,0xe000,0x2ef3	# va	%v25,%v25,%v30,2
	.word	0xe755,0xa000,0x0e6d	# vx	%v21,%v21,%v26
	.word	0xe766,0xb000,0x0e6d	# vx	%v22,%v22,%v27
	.word	0xe777,0x8000,0x0e6d	# vx	%v23,%v23,%v24
	.word	0xe744,0x9000,0x0e6d	# vx	%v20,%v20,%v25
	.word	0xe755,0x000c,0x2c33	# verll	%v21,%v21,12,2
	.word	0xe766,0x000c,0x2c33	# verll	%v22,%v22,12,2
	.word	0xe777,0x000c,0x2c33	# verll	%v23,%v23,12,2
	.word	0xe744,0x000c,0x2c33	# verll	%v20,%v20,12,2
	.word	0xe700,0x5000,0x2ef3	# va	%v16,%v16,%v21,2
	.word	0xe711,0x6000,0x2ef3	# va	%v17,%v17,%v22,2
	.word	0xe722,0x7000,0x2ef3	# va	%v18,%v18,%v23,2
	.word	0xe733,0x4000,0x2ef3	# va	%v19,%v19,%v20,2
	.word	0xe7ff,000000,0x0e6d	# vx	%v31,%v31,%v16
	.word	0xe7cc,0x1000,0x0e6d	# vx	%v28,%v28,%v17
	.word	0xe7dd,0x2000,0x0e6d	# vx	%v29,%v29,%v18
	.word	0xe7ee,0x3000,0x0e6d	# vx	%v30,%v30,%v19
	.word	0xe7ff,0x0008,0x2c33	# verll	%v31,%v31,8,2
	.word	0xe7cc,0x0008,0x2c33	# verll	%v28,%v28,8,2
	.word	0xe7dd,0x0008,0x2c33	# verll	%v29,%v29,8,2
	.word	0xe7ee,0x0008,0x2c33	# verll	%v30,%v30,8,2
	.word	0xe7aa,0xf000,0x2ef3	# va	%v26,%v26,%v31,2
	.word	0xe7bb,0xc000,0x2ef3	# va	%v27,%v27,%v28,2
	.word	0xe788,0xd000,0x2ef3	# va	%v24,%v24,%v29,2
	.word	0xe799,0xe000,0x2ef3	# va	%v25,%v25,%v30,2
	.word	0xe755,0xa000,0x0e6d	# vx	%v21,%v21,%v26
	.word	0xe766,0xb000,0x0e6d	# vx	%v22,%v22,%v27
	.word	0xe777,0x8000,0x0e6d	# vx	%v23,%v23,%v24
	.word	0xe744,0x9000,0x0e6d	# vx	%v20,%v20,%v25
	.word	0xe755,0x0007,0x2c33	# verll	%v21,%v21,7,2
	.word	0xe766,0x0007,0x2c33	# verll	%v22,%v22,7,2
	.word	0xe777,0x0007,0x2c33	# verll	%v23,%v23,7,2
	.word	0xe744,0x0007,0x2c33	# verll	%v20,%v20,7,2
	brct	%r6,.Loop_vx_4x
	.word	0xe700,000000,0x2cf3	# va	%v16,%v16,%v0,2
	.word	0xe711,0x1000,0x2cf3	# va	%v17,%v17,%v1,2
	.word	0xe722,0x2000,0x2cf3	# va	%v18,%v18,%v2,2
	.word	0xe733,0x3000,0x2cf3	# va	%v19,%v19,%v3,2
	.word	0xe744,0x4000,0x2cf3	# va	%v20,%v20,%v4,2
	.word	0xe755,0x5000,0x2cf3	# va	%v21,%v21,%v5,2
	.word	0xe766,0x6000,0x2cf3	# va	%v22,%v22,%v6,2
	.word	0xe777,0x7000,0x2cf3	# va	%v23,%v23,%v7,2
	.word	0xe788,0x8000,0x2cf3	# va	%v24,%v24,%v8,2
	.word	0xe799,0x9000,0x2cf3	# va	%v25,%v25,%v9,2
	.word	0xe7aa,0xa000,0x2cf3	# va	%v26,%v26,%v10,2
	.word	0xe7bb,0xb000,0x2cf3	# va	%v27,%v27,%v11,2
	.word	0xe7cc,0xc000,0x2cf3	# va	%v28,%v28,%v12,2
	.word	0xe7dd,0xd000,0x2cf3	# va	%v29,%v29,%v13,2
	.word	0xe7ee,0xe000,0x2cf3	# va	%v30,%v30,%v14,2
	.word	0xe7ff,0xf000,0x2cf3	# va	%v31,%v31,%v15,2
	.word	0xe767,0x7020,0x0036	# vlm	%v6,%v7,32(%r7)
	.word	0xe700,0x1000,0x2661	# vmrh	%v0,%v16,%v17,2
	.word	0xe712,0x3000,0x2661	# vmrh	%v1,%v18,%v19,2
	.word	0xe780,0x1000,0x608c	# vperm	%v8,%v0,%v1,%v6
	.word	0xe7c0,0x1000,0x708c	# vperm	%v12,%v0,%v1,%v7
	.word	0xe704,0x5000,0x2661	# vmrh	%v0,%v20,%v21,2
	.word	0xe716,0x7000,0x2661	# vmrh	%v1,%v22,%v23,2
	.word	0xe790,0x1000,0x608c	# vperm	%v9,%v0,%v1,%v6
	.word	0xe7d0,0x1000,0x708c	# vperm	%v13,%v0,%v1,%v7
	.word	0xe708,0x9000,0x2661	# vmrh	%v0,%v24,%v25,2
	.word	0xe71a,0xb000,0x2661	# vmrh	%v1,%v26,%v27,2
	.word	0xe7a0,0x1000,0x608c	# vperm	%v10,%v0,%v1,%v6
	.word	0xe7e0,0x1000,0x708c	# vperm	%v14,%v0,%v1,%v7
	.word	0xe70c,0xd000,0x2661	# vmrh	%v0,%v28,%v29,2
	.word	0xe71e,0xf000,0x2661	# vmrh	%v1,%v30,%v31,2
	.word	0xe7b0,0x1000,0x608c	# vperm	%v11,%v0,%v1,%v6
	.word	0xe7f0,0x1000,0x708c	# vperm	%v15,%v0,%v1,%v7
	.word	0xe707,0x3000,0x0036	# vlm	%v0,%v7,0(%r3)
	.word	0xe700,0x8000,0x006d	# vx	%v0,%v0,%v8
	.word	0xe711,0x9000,0x006d	# vx	%v1,%v1,%v9
	.word	0xe722,0xa000,0x006d	# vx	%v2,%v2,%v10
	.word	0xe733,0xb000,0x006d	# vx	%v3,%v3,%v11
	.word	0xe744,0xc000,0x006d	# vx	%v4,%v4,%v12
	.word	0xe755,0xd000,0x006d	# vx	%v5,%v5,%v13
	.word	0xe766,0xe000,0x006d	# vx	%v6,%v6,%v14
	.word	0xe777,0xf000,0x006d	# vx	%v7,%v7,%v15
	.word	0xe707,0x2000,0x003e	# vstm	%v0,%v7,0(%r2)
	.word	0xe767,0x7020,0x0036	# vlm	%v6,%v7,32(%r7)
	.word	0xe700,0x1000,0x2660	# vmrl	%v0,%v16,%v17,2
	.word	0xe712,0x3000,0x2660	# vmrl	%v1,%v18,%v19,2
	.word	0xe780,0x1000,0x608c	# vperm	%v8,%v0,%v1,%v6
	.word	0xe7c0,0x1000,0x708c	# vperm	%v12,%v0,%v1,%v7
	.word	0xe704,0x5000,0x2660	# vmrl	%v0,%v20,%v21,2
	.word	0xe716,0x7000,0x2660	# vmrl	%v1,%v22,%v23,2
	.word	0xe790,0x1000,0x608c	# vperm	%v9,%v0,%v1,%v6
	.word	0xe7d0,0x1000,0x708c	# vperm	%v13,%v0,%v1,%v7
	.word	0xe708,0x9000,0x2660	# vmrl	%v0,%v24,%v25,2
	.word	0xe71a,0xb000,0x2660	# vmrl	%v1,%v26,%v27,2
	.word	0xe7a0,0x1000,0x608c	# vperm	%v10,%v0,%v1,%v6
	.word	0xe7e0,0x1000,0x708c	# vperm	%v14,%v0,%v1,%v7
	.word	0xe70c,0xd000,0x2660	# vmrl	%v0,%v28,%v29,2
	.word	0xe71e,0xf000,0x2660	# vmrl	%v1,%v30,%v31,2
	.word	0xe7b0,0x1000,0x608c	# vperm	%v11,%v0,%v1,%v6
	.word	0xe7f0,0x1000,0x708c	# vperm	%v15,%v0,%v1,%v7
	.word	0xe707,0x3080,0x0036	# vlm	%v0,%v7,128(%r3)
	.word	0xe700,0x8000,0x006d	# vx	%v0,%v0,%v8
	.word	0xe711,0x9000,0x006d	# vx	%v1,%v1,%v9
	.word	0xe722,0xa000,0x006d	# vx	%v2,%v2,%v10
	.word	0xe733,0xb000,0x006d	# vx	%v3,%v3,%v11
	.word	0xe744,0xc000,0x006d	# vx	%v4,%v4,%v12
	.word	0xe755,0xd000,0x006d	# vx	%v5,%v5,%v13
	.word	0xe766,0xe000,0x006d	# vx	%v6,%v6,%v14
	.word	0xe777,0xf000,0x006d	# vx	%v7,%v7,%v15
	.word	0xe707,0x2080,0x003e	# vstm	%v0,%v7,128(%r2)
	ahi	%r0,4
	st	%r0,48+8(%r15)
	la	%r3,256(%r3)
	la	%r2,256(%r2)
	brctg	%r1,.Lvx_4x
.ALIGN	16
.Lvx_4x_done:
	lghi	%r1,255
	ngr	%r4,%r1
	jnz	.Lvx_rem
.ALIGN	16
.Lvx_done:
	.word	0xe700,000000,0x0844	# vgbm	%v16,0
	.word	0xe710,000000,0x0844	# vgbm	%v17,0
	.word	0xe720,000000,0x0844	# vgbm	%v18,0
	.word	0xe730,000000,0x0844	# vgbm	%v19,0
	.word	0xe740,000000,0x0844	# vgbm	%v20,0
	.word	0xe750,000000,0x0844	# vgbm	%v21,0
	.word	0xe760,000000,0x0844	# vgbm	%v22,0
	.word	0xe770,000000,0x0844	# vgbm	%v23,0
	.word	0xe780,000000,0x0844	# vgbm	%v24,0
	.word	0xe790,000000,0x0844	# vgbm	%v25,0
	.word	0xe7a0,000000,0x0844	# vgbm	%v26,0
	.word	0xe7b0,000000,0x0844	# vgbm	%v27,0
	.word	0xe7c0,000000,0x0844	# vgbm	%v28,0
	.word	0xe7d0,000000,0x0844	# vgbm	%v29,0
	.word	0xe7e0,000000,0x0844	# vgbm	%v30,0
	.word	0xe7f0,000000,0x0844	# vgbm	%v31,0
	.word	0xe701,0xf018,0x0c3e	# vstm	%v16,%v17,16+8(%r15)
	la	%r15,168(%r15)
	lm	%r6,%r7,6*4(%r15)
	ld	%f4,16*4+2*8(%r15)
	ld	%f6,16*4+3*8(%r15)
	.word	0xe780,000000,0x0044	# vgbm	%v8,0
	.word	0xe790,000000,0x0044	# vgbm	%v9,0
	.word	0xe7a0,000000,0x0044	# vgbm	%v10,0
	.word	0xe7b0,000000,0x0044	# vgbm	%v11,0
	.word	0xe7c0,000000,0x0044	# vgbm	%v12,0
	.word	0xe7d0,000000,0x0044	# vgbm	%v13,0
	.word	0xe7e0,000000,0x0044	# vgbm	%v14,0
	.word	0xe7f0,000000,0x0044	# vgbm	%v15,0
	br	%r14
.ALIGN	16
.Lvx_rem:
	lhi	%r0,64
	sr	%r4,%r0
	brc	2,.Lvx_rem_g64
	lghi	%r1,-96
	la	%r6,48+8(%r15)
	ar	%r4,%r0
	lgr	%r7,%r6
	st	%r14,14*4+168(%r15)
	la	%r15,0(%r1,%r15)
	bras	%r14,_s390x_chacha_novx
	la	%r15,96(%r15)
	l	%r14,14*4+168(%r15)
	lgr	%r6,%r7
	j	.Lvx_done
.ALIGN	16
.Lvx_rem_g64:
	.word	0xe700,0xf008,0x2005	# vlrep	%v0,0+8(%r15),2
	.word	0xe710,0xf00c,0x2005	# vlrep	%v1,4+8(%r15),2
	.word	0xe720,0xf010,0x2005	# vlrep	%v2,8+8(%r15),2
	.word	0xe730,0xf014,0x2005	# vlrep	%v3,12+8(%r15),2
	.word	0xe740,0xf018,0x2005	# vlrep	%v4,16+8(%r15),2
	.word	0xe750,0xf01c,0x2005	# vlrep	%v5,20+8(%r15),2
	.word	0xe760,0xf020,0x2005	# vlrep	%v6,24+8(%r15),2
	.word	0xe770,0xf024,0x2005	# vlrep	%v7,28+8(%r15),2
	.word	0xe780,0xf028,0x2005	# vlrep	%v8,32+8(%r15),2
	.word	0xe790,0xf02c,0x2005	# vlrep	%v9,36+8(%r15),2
	.word	0xe7a0,0xf030,0x2005	# vlrep	%v10,40+8(%r15),2
	.word	0xe7b0,0xf034,0x2005	# vlrep	%v11,44+8(%r15),2
	.word	0xe7c0,0xf038,0x2005	# vlrep	%v12,48+8(%r15),2
	.word	0xe7d0,0xf03c,0x2005	# vlrep	%v13,52+8(%r15),2
	.word	0xe7e0,0xf040,0x2005	# vlrep	%v14,56+8(%r15),2
	.word	0xe7f0,0xf044,0x2005	# vlrep	%v15,60+8(%r15),2
	.word	0xe7f0,0x7010,0x0806	# vl	%v31,16(%r7)
	.word	0xe7cc,0xf000,0x22f3	# va	%v12,%v12,%v31,2
	.word	0xe700,000000,0x0856	# vlr	%v16,%v0
	.word	0xe711,000000,0x0856	# vlr	%v17,%v1
	.word	0xe722,000000,0x0856	# vlr	%v18,%v2
	.word	0xe733,000000,0x0856	# vlr	%v19,%v3
	.word	0xe744,000000,0x0856	# vlr	%v20,%v4
	.word	0xe755,000000,0x0856	# vlr	%v21,%v5
	.word	0xe766,000000,0x0856	# vlr	%v22,%v6
	.word	0xe777,000000,0x0856	# vlr	%v23,%v7
	.word	0xe788,000000,0x0856	# vlr	%v24,%v8
	.word	0xe799,000000,0x0856	# vlr	%v25,%v9
	.word	0xe7aa,000000,0x0856	# vlr	%v26,%v10
	.word	0xe7bb,000000,0x0856	# vlr	%v27,%v11
	.word	0xe7cc,000000,0x0856	# vlr	%v28,%v12
	.word	0xe7dd,000000,0x0856	# vlr	%v29,%v13
	.word	0xe7ee,000000,0x0856	# vlr	%v30,%v14
	.word	0xe7ff,000000,0x0856	# vlr	%v31,%v15
	lhi	%r6,10
	j	.Loop_vx_rem
.ALIGN	16
.Loop_vx_rem:
	.word	0xe700,0x4000,0x2ef3	# va	%v16,%v16,%v20,2
	.word	0xe711,0x5000,0x2ef3	# va	%v17,%v17,%v21,2
	.word	0xe722,0x6000,0x2ef3	# va	%v18,%v18,%v22,2
	.word	0xe733,0x7000,0x2ef3	# va	%v19,%v19,%v23,2
	.word	0xe7cc,000000,0x0e6d	# vx	%v28,%v28,%v16
	.word	0xe7dd,0x1000,0x0e6d	# vx	%v29,%v29,%v17
	.word	0xe7ee,0x2000,0x0e6d	# vx	%v30,%v30,%v18
	.word	0xe7ff,0x3000,0x0e6d	# vx	%v31,%v31,%v19
	.word	0xe7cc,0x0010,0x2c33	# verll	%v28,%v28,16,2
	.word	0xe7dd,0x0010,0x2c33	# verll	%v29,%v29,16,2
	.word	0xe7ee,0x0010,0x2c33	# verll	%v30,%v30,16,2
	.word	0xe7ff,0x0010,0x2c33	# verll	%v31,%v31,16,2
	.word	0xe788,0xc000,0x2ef3	# va	%v24,%v24,%v28,2
	.word	0xe799,0xd000,0x2ef3	# va	%v25,%v25,%v29,2
	.word	0xe7aa,0xe000,0x2ef3	# va	%v26,%v26,%v30,2
	.word	0xe7bb,0xf000,0x2ef3	# va	%v27,%v27,%v31,2
	.word	0xe744,0x8000,0x0e6d	# vx	%v20,%v20,%v24
	.word	0xe755,0x9000,0x0e6d	# vx	%v21,%v21,%v25
	.word	0xe766,0xa000,0x0e6d	# vx	%v22,%v22,%v26
	.word	0xe777,0xb000,0x0e6d	# vx	%v23,%v23,%v27
	.word	0xe744,0x000c,0x2c33	# verll	%v20,%v20,12,2
	.word	0xe755,0x000c,0x2c33	# verll	%v21,%v21,12,2
	.word	0xe766,0x000c,0x2c33	# verll	%v22,%v22,12,2
	.word	0xe777,0x000c,0x2c33	# verll	%v23,%v23,12,2
	.word	0xe700,0x4000,0x2ef3	# va	%v16,%v16,%v20,2
	.word	0xe711,0x5000,0x2ef3	# va	%v17,%v17,%v21,2
	.word	0xe722,0x6000,0x2ef3	# va	%v18,%v18,%v22,2
	.word	0xe733,0x7000,0x2ef3	# va	%v19,%v19,%v23,2
	.word	0xe7cc,000000,0x0e6d	# vx	%v28,%v28,%v16
	.word	0xe7dd,0x1000,0x0e6d	# vx	%v29,%v29,%v17
	.word	0xe7ee,0x2000,0x0e6d	# vx	%v30,%v30,%v18
	.word	0xe7ff,0x3000,0x0e6d	# vx	%v31,%v31,%v19
	.word	0xe7cc,0x0008,0x2c33	# verll	%v28,%v28,8,2
	.word	0xe7dd,0x0008,0x2c33	# verll	%v29,%v29,8,2
	.word	0xe7ee,0x0008,0x2c33	# verll	%v30,%v30,8,2
	.word	0xe7ff,0x0008,0x2c33	# verll	%v31,%v31,8,2
	.word	0xe788,0xc000,0x2ef3	# va	%v24,%v24,%v28,2
	.word	0xe799,0xd000,0x2ef3	# va	%v25,%v25,%v29,2
	.word	0xe7aa,0xe000,0x2ef3	# va	%v26,%v26,%v30,2
	.word	0xe7bb,0xf000,0x2ef3	# va	%v27,%v27,%v31,2
	.word	0xe744,0x8000,0x0e6d	# vx	%v20,%v20,%v24
	.word	0xe755,0x9000,0x0e6d	# vx	%v21,%v21,%v25
	.word	0xe766,0xa000,0x0e6d	# vx	%v22,%v22,%v26
	.word	0xe777,0xb000,0x0e6d	# vx	%v23,%v23,%v27
	.word	0xe744,0x0007,0x2c33	# verll	%v20,%v20,7,2
	.word	0xe755,0x0007,0x2c33	# verll	%v21,%v21,7,2
	.word	0xe766,0x0007,0x2c33	# verll	%v22,%v22,7,2
	.word	0xe777,0x0007,0x2c33	# verll	%v23,%v23,7,2
	.word	0xe700,0x5000,0x2ef3	# va	%v16,%v16,%v21,2
	.word	0xe711,0x6000,0x2ef3	# va	%v17,%v17,%v22,2
	.word	0xe722,0x7000,0x2ef3	# va	%v18,%v18,%v23,2
	.word	0xe733,0x4000,0x2ef3	# va	%v19,%v19,%v20,2
	.word	0xe7ff,000000,0x0e6d	# vx	%v31,%v31,%v16
	.word	0xe7cc,0x1000,0x0e6d	# vx	%v28,%v28,%v17
	.word	0xe7dd,0x2000,0x0e6d	# vx	%v29,%v29,%v18
	.word	0xe7ee,0x3000,0x0e6d	# vx	%v30,%v30,%v19
	.word	0xe7ff,0x0010,0x2c33	# verll	%v31,%v31,16,2
	.word	0xe7cc,0x0010,0x2c33	# verll	%v28,%v28,16,2
	.word	0xe7dd,0x0010,0x2c33	# verll	%v29,%v29,16,2
	.word	0xe7ee,0x0010,0x2c33	# verll	%v30,%v30,16,2
	.word	0xe7aa,0xf000,0x2ef3	# va	%v26,%v26,%v31,2
	.word	0xe7bb,0xc000,0x2ef3	# va	%v27,%v27,%v28,2
	.word	0xe788,0xd000,0x2ef3	# va	%v24,%v24,%v29,2
	.word	0xe799,0xe000,0x2ef3	# va	%v25,%v25,%v30,2
	.word	0xe755,0xa000,0x0e6d	# vx	%v21,%v21,%v26
	.word	0xe766,0xb000,0x0e6d	# vx	%v22,%v22,%v27
	.word	0xe777,0x8000,0x0e6d	# vx	%v23,%v23,%v24
	.word	0xe744,0x9000,0x0e6d	# vx	%v20,%v20,%v25
	.word	0xe755,0x000c,0x2c33	# verll	%v21,%v21,12,2
	.word	0xe766,0x000c,0x2c33	# verll	%v22,%v22,12,2
	.word	0xe777,0x000c,0x2c33	# verll	%v23,%v23,12,2
	.word	0xe744,0x000c,0x2c33	# verll	%v20,%v20,12,2
	.word	0xe700,0x5000,0x2ef3	# va	%v16,%v16,%v21,2
	.word	0xe711,0x6000,0x2ef3	# va	%v17,%v17,%v22,2
	.word	0xe722,0x7000,0x2ef3	# va	%v18,%v18,%v23,2
	.word	0xe733,0x4000,0x2ef3	# va	%v19,%v19,%v20,2
	.word	0xe7ff,000000,0x0e6d	# vx	%v31,%v31,%v16
	.word	0xe7cc,0x1000,0x0e6d	# vx	%v28,%v28,%v17
	.word	0xe7dd,0x2000,0x0e6d	# vx	%v29,%v29,%v18
	.word	0xe7ee,0x3000,0x0e6d	# vx	%v30,%v30,%v19
	.word	0xe7ff,0x0008,0x2c33	# verll	%v31,%v31,8,2
	.word	0xe7cc,0x0008,0x2c33	# verll	%v28,%v28,8,2
	.word	0xe7dd,0x0008,0x2c33	# verll	%v29,%v29,8,2
	.word	0xe7ee,0x0008,0x2c33	# verll	%v30,%v30,8,2
	.word	0xe7aa,0xf000,0x2ef3	# va	%v26,%v26,%v31,2
	.word	0xe7bb,0xc000,0x2ef3	# va	%v27,%v27,%v28,2
	.word	0xe788,0xd000,0x2ef3	# va	%v24,%v24,%v29,2
	.word	0xe799,0xe000,0x2ef3	# va	%v25,%v25,%v30,2
	.word	0xe755,0xa000,0x0e6d	# vx	%v21,%v21,%v26
	.word	0xe766,0xb000,0x0e6d	# vx	%v22,%v22,%v27
	.word	0xe777,0x8000,0x0e6d	# vx	%v23,%v23,%v24
	.word	0xe744,0x9000,0x0e6d	# vx	%v20,%v20,%v25
	.word	0xe755,0x0007,0x2c33	# verll	%v21,%v21,7,2
	.word	0xe766,0x0007,0x2c33	# verll	%v22,%v22,7,2
	.word	0xe777,0x0007,0x2c33	# verll	%v23,%v23,7,2
	.word	0xe744,0x0007,0x2c33	# verll	%v20,%v20,7,2
	brct	%r6,.Loop_vx_rem
	.word	0xe700,000000,0x2cf3	# va	%v16,%v16,%v0,2
	.word	0xe711,0x1000,0x2cf3	# va	%v17,%v17,%v1,2
	.word	0xe722,0x2000,0x2cf3	# va	%v18,%v18,%v2,2
	.word	0xe733,0x3000,0x2cf3	# va	%v19,%v19,%v3,2
	.word	0xe744,0x4000,0x2cf3	# va	%v20,%v20,%v4,2
	.word	0xe755,0x5000,0x2cf3	# va	%v21,%v21,%v5,2
	.word	0xe766,0x6000,0x2cf3	# va	%v22,%v22,%v6,2
	.word	0xe777,0x7000,0x2cf3	# va	%v23,%v23,%v7,2
	.word	0xe788,0x8000,0x2cf3	# va	%v24,%v24,%v8,2
	.word	0xe799,0x9000,0x2cf3	# va	%v25,%v25,%v9,2
	.word	0xe7aa,0xa000,0x2cf3	# va	%v26,%v26,%v10,2
	.word	0xe7bb,0xb000,0x2cf3	# va	%v27,%v27,%v11,2
	.word	0xe7cc,0xc000,0x2cf3	# va	%v28,%v28,%v12,2
	.word	0xe7dd,0xd000,0x2cf3	# va	%v29,%v29,%v13,2
	.word	0xe7ee,0xe000,0x2cf3	# va	%v30,%v30,%v14,2
	.word	0xe7ff,0xf000,0x2cf3	# va	%v31,%v31,%v15,2
	.word	0xe767,0x7020,0x0036	# vlm	%v6,%v7,32(%r7)
	.word	0xe700,0x1000,0x2661	# vmrh	%v0,%v16,%v17,2
	.word	0xe712,0x3000,0x2661	# vmrh	%v1,%v18,%v19,2
	.word	0xe780,0x1000,0x608c	# vperm	%v8,%v0,%v1,%v6
	.word	0xe7c0,0x1000,0x708c	# vperm	%v12,%v0,%v1,%v7
	.word	0xe704,0x5000,0x2661	# vmrh	%v0,%v20,%v21,2
	.word	0xe716,0x7000,0x2661	# vmrh	%v1,%v22,%v23,2
	.word	0xe790,0x1000,0x608c	# vperm	%v9,%v0,%v1,%v6
	.word	0xe7d0,0x1000,0x708c	# vperm	%v13,%v0,%v1,%v7
	.word	0xe708,0x9000,0x2661	# vmrh	%v0,%v24,%v25,2
	.word	0xe71a,0xb000,0x2661	# vmrh	%v1,%v26,%v27,2
	.word	0xe7a0,0x1000,0x608c	# vperm	%v10,%v0,%v1,%v6
	.word	0xe7e0,0x1000,0x708c	# vperm	%v14,%v0,%v1,%v7
	.word	0xe70c,0xd000,0x2661	# vmrh	%v0,%v28,%v29,2
	.word	0xe71e,0xf000,0x2661	# vmrh	%v1,%v30,%v31,2
	.word	0xe7b0,0x1000,0x608c	# vperm	%v11,%v0,%v1,%v6
	.word	0xe7f0,0x1000,0x708c	# vperm	%v15,%v0,%v1,%v7
	.word	0xe703,0x3000,0x0036	# vlm	%v0,%v3,0(%r3)
	.word	0xe700,0x8000,0x006d	# vx	%v0,%v0,%v8
	.word	0xe711,0x9000,0x006d	# vx	%v1,%v1,%v9
	.word	0xe722,0xa000,0x006d	# vx	%v2,%v2,%v10
	.word	0xe733,0xb000,0x006d	# vx	%v3,%v3,%v11
	.word	0xe703,0x2000,0x003e	# vstm	%v0,%v3,0(%r2)
	la	%r3,64(%r3)
	la	%r2,64(%r2)
	sr	%r4,%r0
	brc	4,.Lvx_tail
	.word	0xe703,0x3000,0x0036	# vlm	%v0,%v3,0(%r3)
	.word	0xe700,0xc000,0x006d	# vx	%v0,%v0,%v12
	.word	0xe711,0xd000,0x006d	# vx	%v1,%v1,%v13
	.word	0xe722,0xe000,0x006d	# vx	%v2,%v2,%v14
	.word	0xe733,0xf000,0x006d	# vx	%v3,%v3,%v15
	.word	0xe703,0x2000,0x003e	# vstm	%v0,%v3,0(%r2)
	jz	.Lvx_done
	.word	0xe700,0x1000,0x2660	# vmrl	%v0,%v16,%v17,2
	.word	0xe712,0x3000,0x2660	# vmrl	%v1,%v18,%v19,2
	.word	0xe7c0,0x1000,0x608c	# vperm	%v12,%v0,%v1,%v6
	.word	0xe780,0x1000,0x708c	# vperm	%v8,%v0,%v1,%v7
	.word	0xe704,0x5000,0x2660	# vmrl	%v0,%v20,%v21,2
	.word	0xe716,0x7000,0x2660	# vmrl	%v1,%v22,%v23,2
	.word	0xe7d0,0x1000,0x608c	# vperm	%v13,%v0,%v1,%v6
	.word	0xe790,0x1000,0x708c	# vperm	%v9,%v0,%v1,%v7
	.word	0xe708,0x9000,0x2660	# vmrl	%v0,%v24,%v25,2
	.word	0xe71a,0xb000,0x2660	# vmrl	%v1,%v26,%v27,2
	.word	0xe7e0,0x1000,0x608c	# vperm	%v14,%v0,%v1,%v6
	.word	0xe7a0,0x1000,0x708c	# vperm	%v10,%v0,%v1,%v7
	.word	0xe70c,0xd000,0x2660	# vmrl	%v0,%v28,%v29,2
	.word	0xe71e,0xf000,0x2660	# vmrl	%v1,%v30,%v31,2
	.word	0xe7f0,0x1000,0x608c	# vperm	%v15,%v0,%v1,%v6
	.word	0xe7b0,0x1000,0x708c	# vperm	%v11,%v0,%v1,%v7
	la	%r3,64(%r3)
	la	%r2,64(%r2)
	sr	%r4,%r0
	brc	4,.Lvx_tail
	.word	0xe703,0x3000,0x0036	# vlm	%v0,%v3,0(%r3)
	.word	0xe700,0xc000,0x006d	# vx	%v0,%v0,%v12
	.word	0xe711,0xd000,0x006d	# vx	%v1,%v1,%v13
	.word	0xe722,0xe000,0x006d	# vx	%v2,%v2,%v14
	.word	0xe733,0xf000,0x006d	# vx	%v3,%v3,%v15
	.word	0xe703,0x2000,0x003e	# vstm	%v0,%v3,0(%r2)
	jz	.Lvx_done
	la	%r3,64(%r3)
	la	%r2,64(%r2)
	sr	%r4,%r0
	.word	0xe7c8,000000,0x0056	# vlr	%v12,%v8
	.word	0xe7d9,000000,0x0056	# vlr	%v13,%v9
	.word	0xe7ea,000000,0x0056	# vlr	%v14,%v10
	.word	0xe7fb,000000,0x0056	# vlr	%v15,%v11
	j	.Lvx_tail
.ALIGN	16
.Lvx_tail:
	ar	%r4,%r0
	ahi	%r4,-1
	lhi	%r0,16
	.word	0xe704,0x3000,0x0037	# vll	%v0,%r4,0(%r3)
	.word	0xe700,0xc000,0x006d	# vx	%v0,%v0,%v12
	.word	0xe704,0x2000,0x003f	# vstl	%v0,%r4,0(%r2)
	sr	%r4,%r0
	brc	4,.Lvx_done
	.word	0xe704,0x3010,0x0037	# vll	%v0,%r4,16(%r3)
	.word	0xe700,0xd000,0x006d	# vx	%v0,%v0,%v13
	.word	0xe704,0x2010,0x003f	# vstl	%v0,%r4,16(%r2)
	sr	%r4,%r0
	brc	4,.Lvx_done
	.word	0xe704,0x3020,0x0037	# vll	%v0,%r4,32(%r3)
	.word	0xe700,0xe000,0x006d	# vx	%v0,%v0,%v14
	.word	0xe704,0x2020,0x003f	# vstl	%v0,%r4,32(%r2)
	sr	%r4,%r0
	brc	4,.Lvx_done
	.word	0xe704,0x3030,0x0037	# vll	%v0,%r4,3*16(%r3)
	.word	0xe700,0xf000,0x006d	# vx	%v0,%v0,%v15
	.word	0xe704,0x2030,0x003f	# vstl	%v0,%r4,3*16(%r2)
	j	.Lvx_done
.SIZE	ChaCha20_ctr32,.-ChaCha20_ctr32
.TYPE	_s390x_chacha_novx,@function
.ALIGN	32
_s390x_chacha_novx:
	ltr	%r4,%r4
	bzr	%r14
	ahi	%r4,-64
	lhi	%r1,-176
	stm	%r6,%r15,6*4(%r15)
	slr	%r2,%r3
	la	%r4,0(%r3,%r4)
	larl	%r7,.Lsigma
	lgr	%r0,%r15
	la	%r15,0(%r1,%r15)
	st	%r0,0(%r15)
	lmg	%r8,%r11,0(%r5)
	lmg	%r12,%r13,0(%r6)
	lmg	%r6,%r7,0(%r7)
	la	%r14,0(%r3)
	st	%r2,176+3*4(%r15)
	st	%r4,176+4*4(%r15)
	stmg	%r6,%r13,96(%r15)
	srlg	%r10,%r12,32
	j	.Loop_outer
.ALIGN	16
.Loop_outer:
	lm	%r0,%r7,96+4*0(%r15)
	lm	%r8,%r9,96+4*10(%r15)
	lm	%r11,%r13,96+4*13(%r15)
	stm	%r8,%r9,96+4*8+4*10(%r15)
	lm	%r8,%r9,96+4*8(%r15)
	st	%r10,96+4*12(%r15)
	st	%r14,176+2*4(%r15)
	lhi	%r14,10
	j	.Loop
.ALIGN	4
.Loop:
	alr	%r0,%r4
	alr	%r1,%r5
	xr	%r10,%r0
	xr	%r11,%r1
	rll	%r10,%r10,16
	rll	%r11,%r11,16
	alr	%r8,%r10
	alr	%r9,%r11
	xr	%r4,%r8
	xr	%r5,%r9
	rll	%r4,%r4,12
	rll	%r5,%r5,12
	alr	%r0,%r4
	alr	%r1,%r5
	xr	%r10,%r0
	xr	%r11,%r1
	rll	%r10,%r10,8
	rll	%r11,%r11,8
	alr	%r8,%r10
	alr	%r9,%r11
	xr	%r4,%r8
	xr	%r5,%r9
	rll	%r4,%r4,7
	rll	%r5,%r5,7
	stm	%r8,%r9,96+4*8+4*8(%r15)
	lm	%r8,%r9,96+4*8+4*10(%r15)
	alr	%r2,%r6
	alr	%r3,%r7
	xr	%r12,%r2
	xr	%r13,%r3
	rll	%r12,%r12,16
	rll	%r13,%r13,16
	alr	%r8,%r12
	alr	%r9,%r13
	xr	%r6,%r8
	xr	%r7,%r9
	rll	%r6,%r6,12
	rll	%r7,%r7,12
	alr	%r2,%r6
	alr	%r3,%r7
	xr	%r12,%r2
	xr	%r13,%r3
	rll	%r12,%r12,8
	rll	%r13,%r13,8
	alr	%r8,%r12
	alr	%r9,%r13
	xr	%r6,%r8
	xr	%r7,%r9
	rll	%r6,%r6,7
	rll	%r7,%r7,7
	alr	%r0,%r5
	alr	%r1,%r6
	xr	%r13,%r0
	xr	%r10,%r1
	rll	%r13,%r13,16
	rll	%r10,%r10,16
	alr	%r8,%r13
	alr	%r9,%r10
	xr	%r5,%r8
	xr	%r6,%r9
	rll	%r5,%r5,12
	rll	%r6,%r6,12
	alr	%r0,%r5
	alr	%r1,%r6
	xr	%r13,%r0
	xr	%r10,%r1
	rll	%r13,%r13,8
	rll	%r10,%r10,8
	alr	%r8,%r13
	alr	%r9,%r10
	xr	%r5,%r8
	xr	%r6,%r9
	rll	%r5,%r5,7
	rll	%r6,%r6,7
	stm	%r8,%r9,96+4*8+4*10(%r15)
	lm	%r8,%r9,96+4*8+4*8(%r15)
	alr	%r2,%r7
	alr	%r3,%r4
	xr	%r11,%r2
	xr	%r12,%r3
	rll	%r11,%r11,16
	rll	%r12,%r12,16
	alr	%r8,%r11
	alr	%r9,%r12
	xr	%r7,%r8
	xr	%r4,%r9
	rll	%r7,%r7,12
	rll	%r4,%r4,12
	alr	%r2,%r7
	alr	%r3,%r4
	xr	%r11,%r2
	xr	%r12,%r3
	rll	%r11,%r11,8
	rll	%r12,%r12,8
	alr	%r8,%r11
	alr	%r9,%r12
	xr	%r7,%r8
	xr	%r4,%r9
	rll	%r7,%r7,7
	rll	%r4,%r4,7
	brct	%r14,.Loop
	l	%r14,176+2*4(%r15)
	stm	%r8,%r9,96+4*8+4*8(%r15)
	lm	%r8,%r9,176+3*4(%r15)
	al	%r0,96+4*0(%r15)
	al	%r1,96+4*1(%r15)
	al	%r2,96+4*2(%r15)
	al	%r3,96+4*3(%r15)
	al	%r4,96+4*4(%r15)
	al	%r5,96+4*5(%r15)
	al	%r6,96+4*6(%r15)
	al	%r7,96+4*7(%r15)
	lrvr	%r0,%r0
	lrvr	%r1,%r1
	lrvr	%r2,%r2
	lrvr	%r3,%r3
	lrvr	%r4,%r4
	lrvr	%r5,%r5
	lrvr	%r6,%r6
	lrvr	%r7,%r7
	al	%r10,96+4*12(%r15)
	al	%r11,96+4*13(%r15)
	al	%r12,96+4*14(%r15)
	al	%r13,96+4*15(%r15)
	lrvr	%r10,%r10
	lrvr	%r11,%r11
	lrvr	%r12,%r12
	lrvr	%r13,%r13
	la	%r8,0(%r8,%r14)
	clr	%r14,%r9
	jh	.Ltail
	x	%r0,4*0(%r14)
	x	%r1,4*1(%r14)
	st	%r0,4*0(%r8)
	x	%r2,4*2(%r14)
	st	%r1,4*1(%r8)
	x	%r3,4*3(%r14)
	st	%r2,4*2(%r8)
	x	%r4,4*4(%r14)
	st	%r3,4*3(%r8)
	lm	%r0,%r3,96+4*8+4*8(%r15)
	x	%r5,4*5(%r14)
	st	%r4,4*4(%r8)
	x	%r6,4*6(%r14)
	al	%r0,96+4*8(%r15)
	st	%r5,4*5(%r8)
	x	%r7,4*7(%r14)
	al	%r1,96+4*9(%r15)
	st	%r6,4*6(%r8)
	x	%r10,4*12(%r14)
	al	%r2,96+4*10(%r15)
	st	%r7,4*7(%r8)
	x	%r11,4*13(%r14)
	al	%r3,96+4*11(%r15)
	st	%r10,4*12(%r8)
	x	%r12,4*14(%r14)
	st	%r11,4*13(%r8)
	x	%r13,4*15(%r14)
	st	%r12,4*14(%r8)
	lrvr	%r0,%r0
	st	%r13,4*15(%r8)
	lrvr	%r1,%r1
	lrvr	%r2,%r2
	lrvr	%r3,%r3
	lhi	%r10,1
	x	%r0,4*8(%r14)
	al	%r10,96+4*12(%r15)
	x	%r1,4*9(%r14)
	st	%r0,4*8(%r8)
	x	%r2,4*10(%r14)
	st	%r1,4*9(%r8)
	x	%r3,4*11(%r14)
	st	%r2,4*10(%r8)
	st	%r3,4*11(%r8)
	clr	%r14,%r9
	la	%r14,64(%r14)
	jl	.Loop_outer
.Ldone:
	xgr	%r0,%r0
	xgr	%r1,%r1
	xgr	%r2,%r2
	xgr	%r3,%r3
	stmg	%r0,%r3,96+4*4(%r15)
	stmg	%r0,%r3,96+4*12(%r15)
	lm	%r6,%r15,176+6*4(%r15)
	br	%r14
.ALIGN	16
.Ltail:
	la	%r9,64(%r9)
	stm	%r0,%r7,96+4*0(%r15)
	slr	%r9,%r14
	lm	%r0,%r3,96+4*8+4*8(%r15)
	lhi	%r6,0
	stm	%r10,%r13,96+4*12(%r15)
	al	%r0,96+4*8(%r15)
	al	%r1,96+4*9(%r15)
	al	%r2,96+4*10(%r15)
	al	%r3,96+4*11(%r15)
	lrvr	%r0,%r0
	lrvr	%r1,%r1
	lrvr	%r2,%r2
	lrvr	%r3,%r3
	stm	%r0,%r3,96+4*8(%r15)
.Loop_tail:
	llgc	%r4,0(%r6,%r14)
	llgc	%r5,96(%r6,%r15)
	xr	%r5,%r4
	stc	%r5,0(%r6,%r8)
	la	%r6,1(%r6)
	brct	%r9,.Loop_tail
	j	.Ldone
.SIZE	_s390x_chacha_novx,.-_s390x_chacha_novx
.ALIGN	64
.Lsigma:
.LONG	1634760805,857760878,2036477234,1797285236
.LONG	0,1,2,3
.LONG	50462976,117835012,319951120,387323156
.LONG	185207048,252579084,454695192,522067228
.ASCIZ	"ChaCha20 for s390x, CRYPTOGAMS by <appro@openssl.org>"
.ALIGN	4
