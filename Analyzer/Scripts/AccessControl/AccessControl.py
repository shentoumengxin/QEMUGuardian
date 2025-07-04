import re
import argparse

# --- 规则定义 ---

# 1. 尝试将权限提升为root (uid=0, gid=0) 的相关系统调用
PRIVILEGE_ESCALATION_SYSCALLS = {
    "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"
}

# 2. 尝试访问敏感系统文件的列表 (使用集合以提高查找效率)
SENSITIVE_FILES = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/group",
    "/root/.ssh/authorized_keys",
    "/root/.bash_history"
}

# 3. 用于文件系统访问的系统调用，我们将检查路径遍历
FILE_ACCESS_SYSCALLS = {
    "open", "openat", "stat", "lstat", "access", "readlink", "chmod", "chown"
}

def analyze_access_control_log(log_path):
    """
    分析给定的QEMU格式的系统调用日志，检测权限与访问控制错误。

    Args:
        log_path (str): 形如 "QEMU <syscall>: <args>" 的日志文件路径。

    Returns:
        bool: 如果检测到可疑活动，返回 True，否则返回 False。
    """
    print(f"[*] 开始分析权限控制日志文件: {log_path}")
    vulnerability_found = False
    
    # 正则表达式用于解析 "QEMU <syscall>: <args>" 格式
    qemu_log_re = re.compile(r'^QEMU\s+([a-zA-Z_]\w*):\s+(.*)$')

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = qemu_log_re.search(line.strip())
                
                if not match:
                    continue

                syscall_name = match.group(1)
                arguments = match.group(2)
                
                # --- 开始应用规则 ---

                # 规则1: 检测权限提升
                if syscall_name in PRIVILEGE_ESCALATION_SYSCALLS:
                    # 如果参数是 "0" 或者包含 "(0," 或 ", 0)"，则极有可能是提权到root
                    if arguments.strip() == "0" or re.search(r'[\(\s,]0[,)\s]', arguments):
                        print_alert(
                            severity="高危",
                            alert_type="权限提升",
                            line_num=line_num,
                            evidence=f"系统调用 '{syscall_name}' 尝试将权限设置为root(0)",
                            full_log=line.strip()
                        )
                        vulnerability_found = True
                        continue # 处理完此行，继续下一行

                # 规则2 & 3: 检测文件访问相关问题
                if syscall_name in FILE_ACCESS_SYSCALLS:
                    # 规则2: 检测路径遍历
                    if '../' in arguments:
                        print_alert(
                            severity="中危",
                            alert_type="路径遍历",
                            line_num=line_num,
                            evidence=f"在路径参数中检测到 '../' 序列",
                            full_log=line.strip()
                        )
                        vulnerability_found = True
                    
                    # 规则3: 检测敏感文件访问
                    # 简单地从参数中提取第一个"单词"作为路径
                    path_candidate = arguments.split(',')[0].strip().strip('"')
                    if path_candidate in SENSITIVE_FILES:
                        print_alert(
                            severity="高危",
                            alert_type="敏感文件访问",
                            line_num=line_num,
                            evidence=f"尝试访问受保护的系统文件: {path_candidate}",
                            full_log=line.strip()
                        )
                        vulnerability_found = True

    except FileNotFoundError:
        print(f"[!] 错误: 文件未找到 {log_path}")
        return False
    except Exception as e:
        print(f"[!] 分析时发生未知错误: {e}")
        return False
        
    if not vulnerability_found:
        print("[*] 分析完成。未在日志中发现明确的权限与访问控制错误特征。")
        
    return vulnerability_found

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def create_sample_access_control_log():
    """创建一个包含多种访问控制错误的假日志文件"""
    sample_data = """
# 正常的用户文件访问
QEMU open: /home/user/notes.txt, O_RDONLY
QEMU read: ...
QEMU close: 3

# 攻击者尝试进行路径遍历来读取 /etc/passwd
QEMU open: /var/www/images/../../../../etc/passwd, O_RDONLY

# 攻击者直接尝试读取 /etc/shadow
QEMU open: /etc/shadow, O_RDONLY

# 攻击成功后，尝试将自身权限提升到 root
QEMU setuid: 0

# 另一个提权的例子
QEMU setreuid: 0, 0
"""
    log_filename = "access_control_trace.log"
    with open(log_filename, "w") as f:
        f.write(sample_data.strip())
    print(f"[*] 已生成演示日志文件: {log_filename}")
    return log_filename

if __name__ == '__main__':
    # 创建演示文件
    default_logfile = create_sample_access_control_log()

    # 设置命令行参数解析
    parser = argparse.ArgumentParser(
        description="一个用于检测权限与访问控制错误的syscall分析器。",
        epilog=f"示例用法: python your_script_name.py {default_logfile}"
    )
    parser.add_argument(
        "logfile", 
        nargs='?', 
        default=default_logfile, 
        help=f"要分析的QEMU格式日志文件路径 (默认为: {default_logfile})"
    )
    
    args = parser.parse_args()
    
    analyze_access_control_log(args.logfile)