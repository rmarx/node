.machine	"any"
.csect	.text[PR],7

.globl	.sha512_block_p8
.align	6
.sha512_block_p8:
	stwu	1,-328(1)
	mflr	8
	li	10,175
	li	11,191
	stvx	24,10,1
	addi	10,10,32
	li	12,-1
	stvx	25,11,1
	addi	11,11,32
	stvx	26,10,1
	addi	10,10,32
	stvx	27,11,1
	addi	11,11,32
	stvx	28,10,1
	addi	10,10,32
	stvx	29,11,1
	addi	11,11,32
	stvx	30,10,1
	stvx	31,11,1
	li	11,-4096+255
	stw	12,348(1)
	li	10,0x10
	stw	26,304(1)
	li	26,0x20
	stw	27,308(1)
	li	27,0x30
	stw	28,312(1)
	li	28,0x40
	stw	29,316(1)
	li	29,0x50
	stw	30,320(1)
	li	30,0x60
	stw	31,324(1)
	li	31,0x70
	stw	8,332(1)
	or	11,11,11

	bl	LPICmeup
	addi	11,1,47
	.long	0x7C001E99
	.long	0x7C4A1E99
	.long	0x7C9A1E99
	vsldoi	1,0,0,8
	.long	0x7CDB1E99
	vsldoi	3,2,2,8
	vsldoi	5,4,4,8
	vsldoi	7,6,6,8
	li	0,4
	b	Loop
.align	5
Loop:
	lvx	28,0,6
	.long	0x7D002699
	addi	4,4,16
	mr	7,6
	stvx	0,0,11
	stvx	1,10,11
	stvx	2,26,11
	stvx	3,27,11
	stvx	4,28,11
	stvx	5,29,11
	stvx	6,30,11
	stvx	7,31,11
	.long	0x10E7E0C0
	lvx	28,10,6
	.long	0x10E740C0
	vsel	29,6,5,4
	.long	0x10C6E0C0
	.long	0x10E7E8C0
	.long	0x13C4FEC2
	.long	0x10E7F0C0
	vxor	29,0,1
	vsel	29,1,2,29
	.long	0x106338C0
	.long	0x13C086C2
	.long	0x13DEE8C0
	.long	0x10E7F0C0
	lvx	28,26,7
	.long	0x7D402699
	addi	4,4,16
	vsldoi	9,8,8,8
	.long	0x10C648C0
	vsel	29,5,4,3
	.long	0x10A5E0C0
	.long	0x10C6E8C0
	.long	0x13C3FEC2
	.long	0x10C6F0C0
	vxor	29,7,0
	vsel	29,0,1,29
	.long	0x104230C0
	.long	0x13C786C2
	.long	0x13DEE8C0
	.long	0x10C6F0C0
	lvx	28,27,7
	.long	0x10A550C0
	vsel	29,4,3,2
	.long	0x1084E0C0
	.long	0x10A5E8C0
	.long	0x13C2FEC2
	.long	0x10A5F0C0
	vxor	29,6,7
	vsel	29,7,0,29
	.long	0x102128C0
	.long	0x13C686C2
	.long	0x13DEE8C0
	.long	0x10A5F0C0
	lvx	28,28,7
	.long	0x7D802699
	addi	4,4,16
	vsldoi	11,10,10,8
	.long	0x108458C0
	vsel	29,3,2,1
	.long	0x1063E0C0
	.long	0x1084E8C0
	.long	0x13C1FEC2
	.long	0x1084F0C0
	vxor	29,5,6
	vsel	29,6,7,29
	.long	0x100020C0
	.long	0x13C586C2
	.long	0x13DEE8C0
	.long	0x1084F0C0
	lvx	28,29,7
	.long	0x106360C0
	vsel	29,2,1,0
	.long	0x1042E0C0
	.long	0x1063E8C0
	.long	0x13C0FEC2
	.long	0x1063F0C0
	vxor	29,4,5
	vsel	29,5,6,29
	.long	0x10E718C0
	.long	0x13C486C2
	.long	0x13DEE8C0
	.long	0x1063F0C0
	lvx	28,30,7
	.long	0x7DC02699
	addi	4,4,16
	vsldoi	13,12,12,8
	.long	0x104268C0
	vsel	29,1,0,7
	.long	0x1021E0C0
	.long	0x1042E8C0
	.long	0x13C7FEC2
	.long	0x1042F0C0
	vxor	29,3,4
	vsel	29,4,5,29
	.long	0x10C610C0
	.long	0x13C386C2
	.long	0x13DEE8C0
	.long	0x1042F0C0
	lvx	28,31,7
	addi	7,7,0x80
	.long	0x102170C0
	vsel	29,0,7,6
	.long	0x1000E0C0
	.long	0x1021E8C0
	.long	0x13C6FEC2
	.long	0x1021F0C0
	vxor	29,2,3
	vsel	29,3,4,29
	.long	0x10A508C0
	.long	0x13C286C2
	.long	0x13DEE8C0
	.long	0x1021F0C0
	lvx	28,0,7
	.long	0x7E002699
	addi	4,4,16
	vsldoi	15,14,14,8
	.long	0x100078C0
	vsel	29,7,6,5
	.long	0x10E7E0C0
	.long	0x1000E8C0
	.long	0x13C5FEC2
	.long	0x1000F0C0
	vxor	29,1,2
	vsel	29,2,3,29
	.long	0x108400C0
	.long	0x13C186C2
	.long	0x13DEE8C0
	.long	0x1000F0C0
	lvx	28,10,7
	.long	0x10E780C0
	vsel	29,6,5,4
	.long	0x10C6E0C0
	.long	0x10E7E8C0
	.long	0x13C4FEC2
	.long	0x10E7F0C0
	vxor	29,0,1
	vsel	29,1,2,29
	.long	0x106338C0
	.long	0x13C086C2
	.long	0x13DEE8C0
	.long	0x10E7F0C0
	lvx	28,26,7
	.long	0x7E402699
	addi	4,4,16
	vsldoi	17,16,16,8
	.long	0x10C688C0
	vsel	29,5,4,3
	.long	0x10A5E0C0
	.long	0x10C6E8C0
	.long	0x13C3FEC2
	.long	0x10C6F0C0
	vxor	29,7,0
	vsel	29,0,1,29
	.long	0x104230C0
	.long	0x13C786C2
	.long	0x13DEE8C0
	.long	0x10C6F0C0
	lvx	28,27,7
	.long	0x10A590C0
	vsel	29,4,3,2
	.long	0x1084E0C0
	.long	0x10A5E8C0
	.long	0x13C2FEC2
	.long	0x10A5F0C0
	vxor	29,6,7
	vsel	29,7,0,29
	.long	0x102128C0
	.long	0x13C686C2
	.long	0x13DEE8C0
	.long	0x10A5F0C0
	lvx	28,28,7
	.long	0x7F002699
	addi	4,4,16
	vsldoi	19,18,18,8
	.long	0x108498C0
	vsel	29,3,2,1
	.long	0x1063E0C0
	.long	0x1084E8C0
	.long	0x13C1FEC2
	.long	0x1084F0C0
	vxor	29,5,6
	vsel	29,6,7,29
	.long	0x100020C0
	.long	0x13C586C2
	.long	0x13DEE8C0
	.long	0x1084F0C0
	lvx	28,29,7
	.long	0x1063C0C0
	vsel	29,2,1,0
	.long	0x1042E0C0
	.long	0x1063E8C0
	.long	0x13C0FEC2
	.long	0x1063F0C0
	vxor	29,4,5
	vsel	29,5,6,29
	.long	0x10E718C0
	.long	0x13C486C2
	.long	0x13DEE8C0
	.long	0x1063F0C0
	lvx	28,30,7
	.long	0x7F402699
	addi	4,4,16
	vsldoi	25,24,24,8
	.long	0x1042C8C0
	vsel	29,1,0,7
	.long	0x1021E0C0
	.long	0x1042E8C0
	.long	0x13C7FEC2
	.long	0x1042F0C0
	vxor	29,3,4
	vsel	29,4,5,29
	.long	0x10C610C0
	.long	0x13C386C2
	.long	0x13DEE8C0
	.long	0x1042F0C0
	lvx	28,31,7
	addi	7,7,0x80
	.long	0x1021D0C0
	vsel	29,0,7,6
	.long	0x1000E0C0
	.long	0x1021E8C0
	.long	0x13C6FEC2
	.long	0x1021F0C0
	vxor	29,2,3
	vsel	29,3,4,29
	.long	0x10A508C0
	.long	0x13C286C2
	.long	0x13DEE8C0
	.long	0x1021F0C0
	lvx	28,0,7
	vsldoi	27,26,26,8
	.long	0x13C906C2
	.long	0x1108F0C0
	.long	0x13DA7EC2
	.long	0x1108F0C0
	.long	0x110888C0
	.long	0x1000D8C0
	vsel	29,7,6,5
	.long	0x10E7E0C0
	.long	0x1000E8C0
	.long	0x13C5FEC2
	.long	0x1000F0C0
	vxor	29,1,2
	vsel	29,2,3,29
	.long	0x108400C0
	.long	0x13C186C2
	.long	0x13DEE8C0
	.long	0x1000F0C0
	lvx	28,10,7
	mtctr	0
	b	L16_xx
.align	5
L16_xx:
	.long	0x13CA06C2
	.long	0x1129F0C0
	.long	0x13DB7EC2
	.long	0x1129F0C0
	.long	0x112990C0
	.long	0x10E740C0
	vsel	29,6,5,4
	.long	0x10C6E0C0
	.long	0x10E7E8C0
	.long	0x13C4FEC2
	.long	0x10E7F0C0
	vxor	29,0,1
	vsel	29,1,2,29
	.long	0x106338C0
	.long	0x13C086C2
	.long	0x13DEE8C0
	.long	0x10E7F0C0
	lvx	28,26,7
	.long	0x13CB06C2
	.long	0x114AF0C0
	.long	0x13C87EC2
	.long	0x114AF0C0
	.long	0x114A98C0
	.long	0x10C648C0
	vsel	29,5,4,3
	.long	0x10A5E0C0
	.long	0x10C6E8C0
	.long	0x13C3FEC2
	.long	0x10C6F0C0
	vxor	29,7,0
	vsel	29,0,1,29
	.long	0x104230C0
	.long	0x13C786C2
	.long	0x13DEE8C0
	.long	0x10C6F0C0
	lvx	28,27,7
	.long	0x13CC06C2
	.long	0x116BF0C0
	.long	0x13C97EC2
	.long	0x116BF0C0
	.long	0x116BC0C0
	.long	0x10A550C0
	vsel	29,4,3,2
	.long	0x1084E0C0
	.long	0x10A5E8C0
	.long	0x13C2FEC2
	.long	0x10A5F0C0
	vxor	29,6,7
	vsel	29,7,0,29
	.long	0x102128C0
	.long	0x13C686C2
	.long	0x13DEE8C0
	.long	0x10A5F0C0
	lvx	28,28,7
	.long	0x13CD06C2
	.long	0x118CF0C0
	.long	0x13CA7EC2
	.long	0x118CF0C0
	.long	0x118CC8C0
	.long	0x108458C0
	vsel	29,3,2,1
	.long	0x1063E0C0
	.long	0x1084E8C0
	.long	0x13C1FEC2
	.long	0x1084F0C0
	vxor	29,5,6
	vsel	29,6,7,29
	.long	0x100020C0
	.long	0x13C586C2
	.long	0x13DEE8C0
	.long	0x1084F0C0
	lvx	28,29,7
	.long	0x13CE06C2
	.long	0x11ADF0C0
	.long	0x13CB7EC2
	.long	0x11ADF0C0
	.long	0x11ADD0C0
	.long	0x106360C0
	vsel	29,2,1,0
	.long	0x1042E0C0
	.long	0x1063E8C0
	.long	0x13C0FEC2
	.long	0x1063F0C0
	vxor	29,4,5
	vsel	29,5,6,29
	.long	0x10E718C0
	.long	0x13C486C2
	.long	0x13DEE8C0
	.long	0x1063F0C0
	lvx	28,30,7
	.long	0x13CF06C2
	.long	0x11CEF0C0
	.long	0x13CC7EC2
	.long	0x11CEF0C0
	.long	0x11CED8C0
	.long	0x104268C0
	vsel	29,1,0,7
	.long	0x1021E0C0
	.long	0x1042E8C0
	.long	0x13C7FEC2
	.long	0x1042F0C0
	vxor	29,3,4
	vsel	29,4,5,29
	.long	0x10C610C0
	.long	0x13C386C2
	.long	0x13DEE8C0
	.long	0x1042F0C0
	lvx	28,31,7
	addi	7,7,0x80
	.long	0x13D006C2
	.long	0x11EFF0C0
	.long	0x13CD7EC2
	.long	0x11EFF0C0
	.long	0x11EF40C0
	.long	0x102170C0
	vsel	29,0,7,6
	.long	0x1000E0C0
	.long	0x1021E8C0
	.long	0x13C6FEC2
	.long	0x1021F0C0
	vxor	29,2,3
	vsel	29,3,4,29
	.long	0x10A508C0
	.long	0x13C286C2
	.long	0x13DEE8C0
	.long	0x1021F0C0
	lvx	28,0,7
	.long	0x13D106C2
	.long	0x1210F0C0
	.long	0x13CE7EC2
	.long	0x1210F0C0
	.long	0x121048C0
	.long	0x100078C0
	vsel	29,7,6,5
	.long	0x10E7E0C0
	.long	0x1000E8C0
	.long	0x13C5FEC2
	.long	0x1000F0C0
	vxor	29,1,2
	vsel	29,2,3,29
	.long	0x108400C0
	.long	0x13C186C2
	.long	0x13DEE8C0
	.long	0x1000F0C0
	lvx	28,10,7
	.long	0x13D206C2
	.long	0x1231F0C0
	.long	0x13CF7EC2
	.long	0x1231F0C0
	.long	0x123150C0
	.long	0x10E780C0
	vsel	29,6,5,4
	.long	0x10C6E0C0
	.long	0x10E7E8C0
	.long	0x13C4FEC2
	.long	0x10E7F0C0
	vxor	29,0,1
	vsel	29,1,2,29
	.long	0x106338C0
	.long	0x13C086C2
	.long	0x13DEE8C0
	.long	0x10E7F0C0
	lvx	28,26,7
	.long	0x13D306C2
	.long	0x1252F0C0
	.long	0x13D07EC2
	.long	0x1252F0C0
	.long	0x125258C0
	.long	0x10C688C0
	vsel	29,5,4,3
	.long	0x10A5E0C0
	.long	0x10C6E8C0
	.long	0x13C3FEC2
	.long	0x10C6F0C0
	vxor	29,7,0
	vsel	29,0,1,29
	.long	0x104230C0
	.long	0x13C786C2
	.long	0x13DEE8C0
	.long	0x10C6F0C0
	lvx	28,27,7
	.long	0x13D806C2
	.long	0x1273F0C0
	.long	0x13D17EC2
	.long	0x1273F0C0
	.long	0x127360C0
	.long	0x10A590C0
	vsel	29,4,3,2
	.long	0x1084E0C0
	.long	0x10A5E8C0
	.long	0x13C2FEC2
	.long	0x10A5F0C0
	vxor	29,6,7
	vsel	29,7,0,29
	.long	0x102128C0
	.long	0x13C686C2
	.long	0x13DEE8C0
	.long	0x10A5F0C0
	lvx	28,28,7
	.long	0x13D906C2
	.long	0x1318F0C0
	.long	0x13D27EC2
	.long	0x1318F0C0
	.long	0x131868C0
	.long	0x108498C0
	vsel	29,3,2,1
	.long	0x1063E0C0
	.long	0x1084E8C0
	.long	0x13C1FEC2
	.long	0x1084F0C0
	vxor	29,5,6
	vsel	29,6,7,29
	.long	0x100020C0
	.long	0x13C586C2
	.long	0x13DEE8C0
	.long	0x1084F0C0
	lvx	28,29,7
	.long	0x13DA06C2
	.long	0x1339F0C0
	.long	0x13D37EC2
	.long	0x1339F0C0
	.long	0x133970C0
	.long	0x1063C0C0
	vsel	29,2,1,0
	.long	0x1042E0C0
	.long	0x1063E8C0
	.long	0x13C0FEC2
	.long	0x1063F0C0
	vxor	29,4,5
	vsel	29,5,6,29
	.long	0x10E718C0
	.long	0x13C486C2
	.long	0x13DEE8C0
	.long	0x1063F0C0
	lvx	28,30,7
	.long	0x13DB06C2
	.long	0x135AF0C0
	.long	0x13D87EC2
	.long	0x135AF0C0
	.long	0x135A78C0
	.long	0x1042C8C0
	vsel	29,1,0,7
	.long	0x1021E0C0
	.long	0x1042E8C0
	.long	0x13C7FEC2
	.long	0x1042F0C0
	vxor	29,3,4
	vsel	29,4,5,29
	.long	0x10C610C0
	.long	0x13C386C2
	.long	0x13DEE8C0
	.long	0x1042F0C0
	lvx	28,31,7
	addi	7,7,0x80
	.long	0x13C806C2
	.long	0x137BF0C0
	.long	0x13D97EC2
	.long	0x137BF0C0
	.long	0x137B80C0
	.long	0x1021D0C0
	vsel	29,0,7,6
	.long	0x1000E0C0
	.long	0x1021E8C0
	.long	0x13C6FEC2
	.long	0x1021F0C0
	vxor	29,2,3
	vsel	29,3,4,29
	.long	0x10A508C0
	.long	0x13C286C2
	.long	0x13DEE8C0
	.long	0x1021F0C0
	lvx	28,0,7
	.long	0x13C906C2
	.long	0x1108F0C0
	.long	0x13DA7EC2
	.long	0x1108F0C0
	.long	0x110888C0
	.long	0x1000D8C0
	vsel	29,7,6,5
	.long	0x10E7E0C0
	.long	0x1000E8C0
	.long	0x13C5FEC2
	.long	0x1000F0C0
	vxor	29,1,2
	vsel	29,2,3,29
	.long	0x108400C0
	.long	0x13C186C2
	.long	0x13DEE8C0
	.long	0x1000F0C0
	lvx	28,10,7
	bc	16,0,L16_xx

	lvx	10,0,11
	subic.	5,5,1
	lvx	11,10,11
	.long	0x100050C0
	lvx	12,26,11
	.long	0x102158C0
	lvx	13,27,11
	.long	0x104260C0
	lvx	14,28,11
	.long	0x106368C0
	lvx	15,29,11
	.long	0x108470C0
	lvx	16,30,11
	.long	0x10A578C0
	lvx	17,31,11
	.long	0x10C680C0
	.long	0x10E788C0
	bne	Loop
	vperm	0,0,1,28
	vperm	2,2,3,28
	vperm	4,4,5,28
	vperm	6,6,7,28
	.long	0x7C001F99
	.long	0x7C4A1F99
	.long	0x7C9A1F99
	.long	0x7CDB1F99
	li	10,175
	mtlr	8
	li	11,191
	or	12,12,12
	lvx	24,10,1
	addi	10,10,32
	lvx	25,11,1
	addi	11,11,32
	lvx	26,10,1
	addi	10,10,32
	lvx	27,11,1
	addi	11,11,32
	lvx	28,10,1
	addi	10,10,32
	lvx	29,11,1
	addi	11,11,32
	lvx	30,10,1
	lvx	31,11,1
	lwz	26,304(1)
	lwz	27,308(1)
	lwz	28,312(1)
	lwz	29,316(1)
	lwz	30,320(1)
	lwz	31,324(1)
	addi	1,1,328
	blr	
.long	0
.byte	0,12,4,1,0x80,6,3,0
.long	0

.align	6
LPICmeup:
	mflr	0
	bcl	20,31,$+4
	mflr	6
	addi	6,6,56
	mtlr	0
	blr	
.long	0
.byte	0,12,0x14,0,0,0,0,0
.space	28
.long	0x428a2f98,0xd728ae22
.long	0x428a2f98,0xd728ae22
.long	0x71374491,0x23ef65cd
.long	0x71374491,0x23ef65cd
.long	0xb5c0fbcf,0xec4d3b2f
.long	0xb5c0fbcf,0xec4d3b2f
.long	0xe9b5dba5,0x8189dbbc
.long	0xe9b5dba5,0x8189dbbc
.long	0x3956c25b,0xf348b538
.long	0x3956c25b,0xf348b538
.long	0x59f111f1,0xb605d019
.long	0x59f111f1,0xb605d019
.long	0x923f82a4,0xaf194f9b
.long	0x923f82a4,0xaf194f9b
.long	0xab1c5ed5,0xda6d8118
.long	0xab1c5ed5,0xda6d8118
.long	0xd807aa98,0xa3030242
.long	0xd807aa98,0xa3030242
.long	0x12835b01,0x45706fbe
.long	0x12835b01,0x45706fbe
.long	0x243185be,0x4ee4b28c
.long	0x243185be,0x4ee4b28c
.long	0x550c7dc3,0xd5ffb4e2
.long	0x550c7dc3,0xd5ffb4e2
.long	0x72be5d74,0xf27b896f
.long	0x72be5d74,0xf27b896f
.long	0x80deb1fe,0x3b1696b1
.long	0x80deb1fe,0x3b1696b1
.long	0x9bdc06a7,0x25c71235
.long	0x9bdc06a7,0x25c71235
.long	0xc19bf174,0xcf692694
.long	0xc19bf174,0xcf692694
.long	0xe49b69c1,0x9ef14ad2
.long	0xe49b69c1,0x9ef14ad2
.long	0xefbe4786,0x384f25e3
.long	0xefbe4786,0x384f25e3
.long	0x0fc19dc6,0x8b8cd5b5
.long	0x0fc19dc6,0x8b8cd5b5
.long	0x240ca1cc,0x77ac9c65
.long	0x240ca1cc,0x77ac9c65
.long	0x2de92c6f,0x592b0275
.long	0x2de92c6f,0x592b0275
.long	0x4a7484aa,0x6ea6e483
.long	0x4a7484aa,0x6ea6e483
.long	0x5cb0a9dc,0xbd41fbd4
.long	0x5cb0a9dc,0xbd41fbd4
.long	0x76f988da,0x831153b5
.long	0x76f988da,0x831153b5
.long	0x983e5152,0xee66dfab
.long	0x983e5152,0xee66dfab
.long	0xa831c66d,0x2db43210
.long	0xa831c66d,0x2db43210
.long	0xb00327c8,0x98fb213f
.long	0xb00327c8,0x98fb213f
.long	0xbf597fc7,0xbeef0ee4
.long	0xbf597fc7,0xbeef0ee4
.long	0xc6e00bf3,0x3da88fc2
.long	0xc6e00bf3,0x3da88fc2
.long	0xd5a79147,0x930aa725
.long	0xd5a79147,0x930aa725
.long	0x06ca6351,0xe003826f
.long	0x06ca6351,0xe003826f
.long	0x14292967,0x0a0e6e70
.long	0x14292967,0x0a0e6e70
.long	0x27b70a85,0x46d22ffc
.long	0x27b70a85,0x46d22ffc
.long	0x2e1b2138,0x5c26c926
.long	0x2e1b2138,0x5c26c926
.long	0x4d2c6dfc,0x5ac42aed
.long	0x4d2c6dfc,0x5ac42aed
.long	0x53380d13,0x9d95b3df
.long	0x53380d13,0x9d95b3df
.long	0x650a7354,0x8baf63de
.long	0x650a7354,0x8baf63de
.long	0x766a0abb,0x3c77b2a8
.long	0x766a0abb,0x3c77b2a8
.long	0x81c2c92e,0x47edaee6
.long	0x81c2c92e,0x47edaee6
.long	0x92722c85,0x1482353b
.long	0x92722c85,0x1482353b
.long	0xa2bfe8a1,0x4cf10364
.long	0xa2bfe8a1,0x4cf10364
.long	0xa81a664b,0xbc423001
.long	0xa81a664b,0xbc423001
.long	0xc24b8b70,0xd0f89791
.long	0xc24b8b70,0xd0f89791
.long	0xc76c51a3,0x0654be30
.long	0xc76c51a3,0x0654be30
.long	0xd192e819,0xd6ef5218
.long	0xd192e819,0xd6ef5218
.long	0xd6990624,0x5565a910
.long	0xd6990624,0x5565a910
.long	0xf40e3585,0x5771202a
.long	0xf40e3585,0x5771202a
.long	0x106aa070,0x32bbd1b8
.long	0x106aa070,0x32bbd1b8
.long	0x19a4c116,0xb8d2d0c8
.long	0x19a4c116,0xb8d2d0c8
.long	0x1e376c08,0x5141ab53
.long	0x1e376c08,0x5141ab53
.long	0x2748774c,0xdf8eeb99
.long	0x2748774c,0xdf8eeb99
.long	0x34b0bcb5,0xe19b48a8
.long	0x34b0bcb5,0xe19b48a8
.long	0x391c0cb3,0xc5c95a63
.long	0x391c0cb3,0xc5c95a63
.long	0x4ed8aa4a,0xe3418acb
.long	0x4ed8aa4a,0xe3418acb
.long	0x5b9cca4f,0x7763e373
.long	0x5b9cca4f,0x7763e373
.long	0x682e6ff3,0xd6b2b8a3
.long	0x682e6ff3,0xd6b2b8a3
.long	0x748f82ee,0x5defb2fc
.long	0x748f82ee,0x5defb2fc
.long	0x78a5636f,0x43172f60
.long	0x78a5636f,0x43172f60
.long	0x84c87814,0xa1f0ab72
.long	0x84c87814,0xa1f0ab72
.long	0x8cc70208,0x1a6439ec
.long	0x8cc70208,0x1a6439ec
.long	0x90befffa,0x23631e28
.long	0x90befffa,0x23631e28
.long	0xa4506ceb,0xde82bde9
.long	0xa4506ceb,0xde82bde9
.long	0xbef9a3f7,0xb2c67915
.long	0xbef9a3f7,0xb2c67915
.long	0xc67178f2,0xe372532b
.long	0xc67178f2,0xe372532b
.long	0xca273ece,0xea26619c
.long	0xca273ece,0xea26619c
.long	0xd186b8c7,0x21c0c207
.long	0xd186b8c7,0x21c0c207
.long	0xeada7dd6,0xcde0eb1e
.long	0xeada7dd6,0xcde0eb1e
.long	0xf57d4f7f,0xee6ed178
.long	0xf57d4f7f,0xee6ed178
.long	0x06f067aa,0x72176fba
.long	0x06f067aa,0x72176fba
.long	0x0a637dc5,0xa2c898a6
.long	0x0a637dc5,0xa2c898a6
.long	0x113f9804,0xbef90dae
.long	0x113f9804,0xbef90dae
.long	0x1b710b35,0x131c471b
.long	0x1b710b35,0x131c471b
.long	0x28db77f5,0x23047d84
.long	0x28db77f5,0x23047d84
.long	0x32caab7b,0x40c72493
.long	0x32caab7b,0x40c72493
.long	0x3c9ebe0a,0x15c9bebc
.long	0x3c9ebe0a,0x15c9bebc
.long	0x431d67c4,0x9c100d4c
.long	0x431d67c4,0x9c100d4c
.long	0x4cc5d4be,0xcb3e42b6
.long	0x4cc5d4be,0xcb3e42b6
.long	0x597f299c,0xfc657e2a
.long	0x597f299c,0xfc657e2a
.long	0x5fcb6fab,0x3ad6faec
.long	0x5fcb6fab,0x3ad6faec
.long	0x6c44198c,0x4a475817
.long	0x6c44198c,0x4a475817
.long	0,0
.long	0,0
.long	0x00010203,0x04050607
.long	0x10111213,0x14151617
.byte	83,72,65,53,49,50,32,102,111,114,32,80,111,119,101,114,73,83,65,32,50,46,48,55,44,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	2
.align	2
