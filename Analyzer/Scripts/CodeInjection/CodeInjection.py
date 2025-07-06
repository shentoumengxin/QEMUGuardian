import json

SUSPICIOUS_COMMANDS = {
    "/bin/sh",
    "/bin/bash",
    "/bin/csh",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "sh",
    "bash",
}

def print_alert(severity, alert_type, line_num, evidence, full_log_dict, pid):
    print("\n" + "="*60)
    print(f"[!!!] {severity} Alert: Potential [{alert_type}] vulnerability detected!")
    print(f"      - Process ID: {pid}")
    print(f"      - Alert Line: {line_num}")
    print(f"      - Evidence: {evidence}")
    print(f"      - Full Log Entry: {json.dumps(full_log_dict)}")
    print("="*60)

def analyze_command_injection(log_path):
    found = False
    with open(log_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                log = json.loads(line)
                pid = log.get('pid')

                if log.get('event') == 'EXEC' and log.get('filename') in SUSPICIOUS_COMMANDS:
                    print_alert("High Risk", "Command Injection", line_num, f"Suspicious shell executed: {log['filename']}", log, pid)
                    found = True
            except json.JSONDecodeError: continue
    if not found: print("No specific threats detected.")

if __name__ == '__main__':
    analyze_command_injection("command_injection_trace.jsonl")
