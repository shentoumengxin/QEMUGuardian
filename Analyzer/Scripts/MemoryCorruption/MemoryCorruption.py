#
# 脚本1: 检测内存损坏利用迹象
#
import re
import argparse

def analyze_memory_corruption_log(log_path):
    """分析日志，检测因内存损坏漏洞利用而产生的可疑系统调用。"""
    print(f"[*] 开始分析内存损坏日志文件: {log_path}")
    vulnerability_found = False
    
    # 正则表达式捕获 mprotect 调用和它的权限参数
    mprotect_re = re.compile(r'^QEMU\s+mprotect:\s+.*(PROT_EXEC).*$')

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = mprotect_re.search(line.strip())
                
                if match:
                    permissions = match.group(1)
                    print_alert(
                        severity="高危",
                        alert_type="内存损坏利用 (Shellcode)",
                        line_num=line_num,
                        evidence=f"检测到 'mprotect' 调用并设置了可执行权限 ({permissions})",
                        full_log=line.strip()
                    )
                    vulnerability_found = True

    except FileNotFoundError:
        print(f"[!] 错误: 文件未找到 {log_path}")
        return False
        
    if not vulnerability_found:
        print("[*] 分析完成。未发现明确的内存损坏利用特征。")
        
    return vulnerability_found

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def create_sample_memory_corruption_log():
    """创建一个模拟内存损坏利用的假日志文件"""
    sample_data = """
# 程序正常读取一些数据
QEMU read: some_normal_data
# 攻击者发送了一个超长的、包含Shellcode的输入，触发了缓冲区溢出
QEMU read: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...[Shellcode]...
# 漏洞利用成功，现在攻击者控制了程序流程
# 为了执行Shellcode，攻击者调用 mprotect 将栈或堆的一部分标记为可执行
QEMU mprotect: 0x7ffc12340000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC
# 在可执行内存上执行Shellcode，最终启动一个shell
QEMU execve: /bin/sh -c "malicious command"
"""
    log_filename = "memory_corruption_trace.log"
    with open(log_filename, "w") as f: f.write(sample_data.strip())
    print(f"[*] 已生成演示日志文件: {log_filename}")
    return log_filename

# (辅助函数 print_alert 和 main 函数与之前的脚本类似，这里为了简洁省略)
# (实际运行时，请确保 print_alert 函数存在)
if __name__ == '__main__':
    default_logfile = create_sample_memory_corruption_log()
    parser = argparse.ArgumentParser(description="检测内存损坏利用迹象的脚本。")
    parser.add_argument("logfile", nargs='?', default=default_logfile, help="要分析的日志文件路径")
    args = parser.parse_args()
    analyze_memory_corruption_log(args.logfile)