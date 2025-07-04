#
# 脚本: 检测信息泄露迹象 (修正版，优先检查最近的读操作)
#
import re
import argparse
from collections import deque

# --- 规则定义 (保持不变) ---
LARGE_WRITE_THRESHOLD = 4096
LOOKBACK_WINDOW = 10
DISPROPORTIONATE_FACTOR = 10

def analyze_info_leak_log_v3(log_path):
    """
    分析日志，检测在一定回看窗口内的、不成比例的 read/write 操作对。
    此版本修正了关联逻辑，优先检查最近的读操作。
    """
    print(f"[*] 开始分析信息泄露日志文件 (回看窗口: {LOOKBACK_WINDOW}行, 修正逻辑)")
    vulnerability_found = False
    
    log_re = re.compile(r'^QEMU\s+(\w+):.*\[size=(\d+)\]$')
    recent_reads = deque(maxlen=LOOKBACK_WINDOW)

    try:
        with open(log_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                match = log_re.search(line.strip())
                if not match:
                    continue
                
                syscall_name = match.group(1)
                size = int(match.group(2))

                if syscall_name in ["read", "recv", "recvfrom"]:
                    recent_reads.append({'size': size, 'line_num': line_num})
                
                elif syscall_name in ["write", "send", "sendto"]:
                    if size > LARGE_WRITE_THRESHOLD:
                        # --- 关键修正 ---
                        # 使用 reversed() 从最新（最右边）的元素开始遍历队列
                        for read_info in reversed(recent_reads):
                            if size > read_info['size'] * DISPROPORTIONATE_FACTOR:
                                print_alert(
                                    severity="高危",
                                    alert_type="信息泄露 (Heartbleed-like)",
                                    line_num=line_num,
                                    evidence=(f"在第 {read_info['line_num']} 行读取少量数据(size={read_info['size']})后，"
                                              f"于此行发送了异常大的数据包(size={size})"),
                                    full_log=line.strip()
                                )
                                vulnerability_found = True
                                # 找到最相关的配对后立即跳出
                                break 

    except FileNotFoundError:
        print(f"[!] 错误: 文件未找到 {log_path}")
        return False
    except Exception as e:
        print(f"[!] 分析时发生未知错误: {e}")
        return False
        
    if not vulnerability_found:
        print("[*] 分析完成。未发现明确的信息泄露特征。")
        
    return vulnerability_found

def create_sample_info_leak_log_v2():
    """创建演示日志文件 (与之前相同)"""
    sample_data = """
# 正常交互
QEMU read: user_request_1 [size=64]
QEMU write: normal_response_1 [size=128]

# 攻击者发送恶意请求
QEMU read: malicious_heartbeat_request [size=16]

# 在写回数据前，程序可能做了其他事
QEMU time: get current time [size=0]
QEMU stat: /proc/self/status [size=0]
QEMU mmap: allocate memory for response [size=0]

# 服务器存在漏洞，最终写回了大量内存数据
QEMU write: LEAKED_MEMORY_CHUNK_INCLUDING_PRIVATE_KEYS... [size=65536]
"""
    log_filename = "info_leak_v2_trace.log"
    with open(log_filename, "w") as f: f.write(sample_data.strip())
    print(f"[*] 已生成演示日志文件: {log_filename}")
    return log_filename

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 告警行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

if __name__ == '__main__':
    default_logfile = create_sample_info_leak_log_v2()
    parser = argparse.ArgumentParser(description="检测信息泄露迹象的脚本 (修正版)。")
    parser.add_argument("logfile", nargs='?', default=default_logfile, help="要分析的日志文件路径")
    args = parser.parse_args()
    analyze_info_leak_log_v3(args.logfile)