import json

PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    print("\n" + "="*60)
    print(f"[!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    print(f"      - Process ID: {pid}")
    print(f"      - Alert Line: {line_num}")
    print(f"      - Evidence: {evidence}")
    print(f"      - Full Log Entry: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_access_control(log_path):
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                event = log.get('event')
                pid = log.get('pid')

                if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
                    print_alert("High Risk", "Privilege Escalation", line_num, f"'{event}' call attempts to set uid to 0 (root)", log, pid)
                    found = True
                
                if event == 'TRACK_OPENAT':
                    filename = log.get('file', '')
                    if '../' in filename:
                        print_alert("Medium Risk", "Path Traversal", line_num, "Path contains '../' sequence", log, pid)
                        found = True
                    if filename in SENSITIVE_FILES:
                        print_alert("High Risk", "Sensitive File Access", line_num, f"Attempt to access sensitive file: {filename}", log, pid)
                        found = True
            except json.JSONDecodeError: continue
    if not found: print("No specific threats detected.")

if __name__ == '__main__':
    analyze_access_control("access_control_trace.jsonl")