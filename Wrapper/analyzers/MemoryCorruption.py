import json 
import sys

def analyze_memory_corruption():
    max_pages_threshold = 65536

    line = sys.stdin.read().strip()
    if not line:
        return
    try:
        log = json.loads(line)
        pid = log.get('pid')

        if log.get('event') == 'MPROTECT':
            if log.get('exec') == 1:
                results = {
                    "level": 9.3,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    "description": "Memory Corruption (Shellcode)",
                    "pid": pid,
                    "evidence": f"Detected 'mprotect' call setting executable permissions (PROT_EXEC)",
                    }
                print(json.dumps(results))
                    
        if log.get('evt') == 'MMAP_SUM':
            max_pages = log.get('meta', {}).get('max_pages', 0)
            if max_pages > max_pages_threshold:
                results = {
                    "level": 9.3,
                    "cvss_vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                    "description": "Memory Corruption (Weak Signal)",
                    "pid": pid,
                    "evidence": f"Detected abnormally large page allocation via mmap: {max_pages} pages",
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
    analyze_memory_corruption()