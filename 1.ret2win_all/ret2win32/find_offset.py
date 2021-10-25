from pwn import *

context.binary = elf = ELF('./ret2win32')

p = elf.process()

g = cyclic_gen()

p.recvuntil('> ')
p.sendline(g.get(100))

p.shutdown()
p.wait()

c = Core('./core')

offset = g.find(p64(c.fault_addr))

log.info("OFFSET FIND > "+str(offset))

