import json

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

def print_alert(severity, alert_type, line_num, evidence, full_log_dict):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 告警行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_command_injection(log_path):
    print("\n--- 开始分析 [命令注入] ---")
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                # EXEC事件表示进程调用了execve
                if log.get('event') == 'EXEC' and log.get('filename') in SUSPICIOUS_COMMANDS:
                    print_alert("高危", "命令注入", line_num, f"执行了可疑的Shell: {log['filename']}", log)
                    found = True
            except json.JSONDecodeError: continue
    if not found: print("未发现明确特征。")

if __name__ == '__main__':
    analyze_command_injection("command_injection_trace.jsonl")
