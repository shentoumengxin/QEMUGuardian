import json
import sys

PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

def analyze_access_control():
    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        event = log.get('event')
        pid = log.get('pid')

        if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
            results = {
                "level": 6.3,
                "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H",
                "description": "Potential Privilege Escalation",
                "pid": pid,
                "evidence": f"'{event}' call attempts to set uid to 0 (root)",
            }
            print(json.dumps(results))
            
        if event == 'TRACK_OPENAT':
            filename = log.get('file', '')
            if '../' in filename:
                results = {
                    "level": 7.7,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
                    "description": "Potential Path Traversal",
                    "pid": pid,
                    "evidence": "Path contains '../' sequence",
                }
                print(json.dumps(results))
            if filename in SENSITIVE_FILES:
                results = {
                    "level": 7.7,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
                    "description": "Access to Sensitive File",
                    "pid": pid,
                    "evidence": f"Attempt to access sensitive file: {filename}",
                }
                print(json.dumps(results))
    except json.JSONDecodeError:
        results = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None,
        }
        print(json.dumps(results))

if __name__ == '__main__':
    analyze_access_control()