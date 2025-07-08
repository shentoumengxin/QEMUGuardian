import json
import sys

PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"}
SENSITIVE_FILES = {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}

def analyze_access_control():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            event = log.get('event')
            pid = log.get('pid')

            if event in PRIVILEGE_ESCALATION_EVENTS and log.get('uid') == 0:
                results = {
                    "level": 8,
                    "description": "Potential Privilege Escalation",
                    "pid": pid,
                    "evidence": f"'{event}' call attempts to set uid to 0 (root)",
                }
                print(json.dumps(results))
            
            if event == 'TRACK_OPENAT':
                filename = log.get('file', '')
                if '../' in filename:
                    results = {
                        "level": 5,
                        "description": "Potential Path Traversal",
                        "pid": pid,
                        "evidence": "Path contains '../' sequence",
                    }
                    print(json.dumps(results))
                if filename in SENSITIVE_FILES:
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
                "description": f"Invalid JSON input: {line}",
                "pid": None,
            }
            print(json.dumps(results))

if __name__ == '__main__':
    analyze_access_control()