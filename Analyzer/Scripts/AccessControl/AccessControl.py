import json

# 规则: 权限提升相关的事件 (假设事件名称)
PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
# 规则: 敏感系统文件
SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

def print_alert(severity, alert_type, line_num, evidence, full_log):
    """格式化并打印安全警报"""
    print("\n" + "="*60)
    print(f"[!!!] {severity}警报：检测到潜在的【{alert_type}】漏洞！")
    print(f"      - 行号: {line_num}")
    print(f"      - 证据: {evidence}")
    print(f"      - 完整日志: {full_log}")
    print("="*60)

def analyze_access_control(log_path):
    print("\n--- 开始分析 [权限与访问控制] ---")
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                event = log.get('event')
                
                # 权限提升 (基于假设的SETUID事件)
                if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
                    print_alert("高危", "权限提升", line_num, f"'{event}' 尝试设置uid为0 (root)", log)
                    found = True
                
                # 文件访问事件为 TRACK_OPENAT
                if event == 'TRACK_OPENAT':
                    filename = log.get('file', '')
                    # 路径遍历
                    if '../' in filename:
                        print_alert("中危", "路径遍历", line_num, f"路径中包含 '../' 序列", log)
                        found = True
                    # 敏感文件访问
                    if filename in SENSITIVE_FILES:
                        print_alert("高危", "敏感文件访问", line_num, f"尝试访问敏感文件: {filename}", log)
                        found = True
            except json.JSONDecodeError: continue
    if not found: print("未发现明确特征。")

if __name__ == '__main__':
    analyze_access_control("access_control_trace.jsonl")