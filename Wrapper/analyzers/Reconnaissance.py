# analyzers/Reconnaissance.py
import json
import sys

# 恶意软件常用于探测环境的符号链接
RECON_PATHS = {
    "/proc/self/exe",  # 获取自身可执行文件路径
    "/proc/self/cwd",  # 获取当前工作目录
    "/proc/self/maps", # 获取内存映射信息 (绕过ASLR)
}

def analyze_reconnaissance():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            log = json.loads(line)
            # 根据接口文档，事件为 READLINKAT
            if log.get('event') == 'READLINKAT':
                pid = log.get('pid')
                path = log.get('path') # 接口文档中定义的字段

                if path in RECON_PATHS:
                    # 将侦察行为评为低危信息泄露
                    result = {
                        "level": 3.4,
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