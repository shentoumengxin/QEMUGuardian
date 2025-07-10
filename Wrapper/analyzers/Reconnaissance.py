# analyzers/Reconnaissance.py
import json
import sys

RECON_PATHS = {
    "/proc/self/exe",  
    "/proc/self/cwd",  
    "/proc/self/maps", 
}

def analyze_reconnaissance():
    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        if log.get('event') == 'READLINKAT':
            pid = log.get('pid')
            path = log.get('path') 

            if path in RECON_PATHS:
                result = {
                    "level": 4.8,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                    "description": "Suspicious Reconnaissance Activity Detected",
                    "pid": pid,
                    "evidence": f"Process performed reconnaissance by reading a sensitive procfs link: {path}.",
                }
                print(json.dumps(result))

    except json.JSONDecodeError:
        result = {
            "level": -1,
            "description": f"Invalid JSON input: {line}",
            "pid": None,
        }
        print(json.dumps(result))

if __name__ == '__main__':
    analyze_reconnaissance()