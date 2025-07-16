# import json
# import sys

# PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
# SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

# def analyze_access_control():
#     line = sys.stdin.read().strip()
#     if not line:
#         return
#     try:
#         log = json.loads(line)
#         event = log.get('event')
#         pid = log.get('pid')

#         if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
#             results = {
#                 "level": 6.3,
#                 "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H",
#                 "description": "Potential Privilege Escalation",
#                 "pid": pid,
#                 "evidence": f"'{event}' call attempts to set uid to 0 (root)",
#             }
#             print(json.dumps(results))
            
#         if event == 'TRACK_OPENAT':
#             filename = log.get('file', '')
#             if '../' in filename:
#                 results = {
#                     "level": 7.7,
#                     "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
#                     "description": "Potential Path Traversal",
#                     "pid": pid,
#                     "evidence": "Path contains '../' sequence",
#                 }
#                 print(json.dumps(results))
#             if filename in SENSITIVE_FILES:
#                 results = {
#                     "level": 7.7,
#                     "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
#                     "description": "Access to Sensitive File",
#                     "pid": pid,
#                     "evidence": f"Attempt to access sensitive file: {filename}",
#                 }
#                 print(json.dumps(results))
#     except json.JSONDecodeError:
#         results = {
#             "level": -1,
#             "description": f"Invalid JSON input: {line}",
#             "pid": None,
#         }
#         print(json.dumps(results))

# if __name__ == '__main__':
#     analyze_access_control()
import json
import sys

PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}
# 新增一个集合，包含所有与文件打开相关的事件
FILE_OPEN_EVENTS = {"TRACK_OPENAT", "TRACK_OPEN"} # 假设 open 事件被命名为 TRACK_OPEN

def analyze_access_control():
    # 为了避免在同一个事件中重复报警，我们使用一个标志
    alerted_in_this_event = False

    # 使用一次性读取，以避免之前讨论过的死锁问题
    input_data = sys.stdin.read()
    if not input_data.strip():
        return

    try:
        log = json.loads(input_data)
        event = log.get('event')
        pid = log.get('pid')

        # --- 权限提升检测 ---
        if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
            results = {
                "level": 8,
                "description": "Potential Privilege Escalation",
                "pid": pid,
                "evidence": f"'{event}' call attempts to set uid to 0 (root)",
            }
            print(json.dumps(results))
            alerted_in_this_event = True

        # --- 文件访问检测 (核心修改) ---
        # 检查事件是否属于文件打开类事件
        if event in FILE_OPEN_EVENTS and not alerted_in_this_event:
            # 假设无论是 open 还是 openat, 文件名都存储在 'file' 字段
            filename = log.get('file', '')
            
            # 1. 路径遍历检测
            if '../' in filename:
                results = {
                    "level": 5,
                    "description": "Potential Path Traversal",
                    "pid": pid,
                    "evidence": f"Path '{filename}' contains '../' sequence",
                }
                print(json.dumps(results))
                # 设置标志，防止对同一个事件的敏感文件访问重复报警
                alerted_in_this_event = True

            # 2. 敏感文件访问检测
            # 检查是否是绝对路径，并且在我们的敏感文件列表中
            if filename in SENSITIVE_FILES and not alerted_in_this_event:
                results = {
                    "level": 8,
                    "description": "Sensitive File Access",
                    "pid": pid,
                    "evidence": f"Attempt to access sensitive file: {filename}",
                }
                print(json.dumps(results))
    
    except json.JSONDecodeError:
        results = {
            "level": -1,
            "description": f"Invalid JSON input: {input_data}",
            "pid": None,
        }
        print(json.dumps(results))

if __name__ == '__main__':
    analyze_access_control()
