#!/usr/bin/env -S python3

import subprocess
import json
import os
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor
import re
from collections import deque
import threading
import uuid
import time
import errno
from pathlib import Path
import resource
import select
REPORT_GUI_PROCESS = None
seen_pids = set()       # 只追加不弹出，保留整个监控周期内见过的 PID
hidden_failures = set()    # 记录那些 kill 失败的高危 PID
_skip_cgroup_warning = False

# Analyzer folder path
ANALYZER_DIR = "./analyzers"

# Vulnerability level threshold (e.g., >= 8 is high-risk)
HIGH_VULNERABILITY_THRESHOLD = 9
cfg_path = Path(__file__).parent / "config.json"
# ========== 新增：cgroup 相关全局变量 ==========
CGROUP_NAME = None  # 将在 main() 中初始化
CGROUP_PATH = None  # 将在 setup_cgroup() 中设置
QEMU_PROCESS = None  # 保存 QEMU 进程对象
CURRENT_EXECUTABLE = None  # 当前正在运行的可执行文件名

# Map event types to analyzer scripts
EVENT_ANALYZER_MAP = {}
EVT_ANALYZER_MAP = {}

def limit_procs(max_procs: int):
    """
    限制当前进程及其所有后代的最大进程数（线程也算）。max_procs 既是软限制也是硬限制——超出 fork() 立刻失败 (EAGAIN)。
    """
    resource.setrlimit(resource.RLIMIT_NPROC, (max_procs, max_procs))

# ========== 自动从 v2 降级到 v1 ==========
def setup_cgroup(cgroup_name, memory_limit="2G", cpu_quota=200000, pids_max=1000):
    """
    优先尝试 cgroup v2（unified），权限不足时自动降级到 cgroup v1 各个子系统。
    返回：
      - 如果 v2 成功：返回字符串路径 CGROUP_PATH
      - 如果降级到 v1：返回 dict {'memory': path, 'cpu': path, 'pids': path}
      - 失败时返回 None
    """
    global CGROUP_PATH

    # 1) 查 unified v2 挂载点
    v2_mount = None
    with open("/proc/mounts") as m:
        for line in m:
            dev, mnt, fs, *_ = line.split()
            if fs == "cgroup2":
                v2_mount = mnt
                break

    if v2_mount:
        # 尝试开启 subtree_control
        try:
            ctrls = open(f"{v2_mount}/cgroup.controllers").read().split()
            want = [f"+{c}" for c in ("memory","cpu","pids") if c in ctrls]
            if want:
                open(f"{v2_mount}/cgroup.subtree_control", "w").write(" ".join(want))
            # 创建子 cgroup
            CGROUP_PATH = f"{v2_mount}/{cgroup_name}"
            os.makedirs(CGROUP_PATH, exist_ok=True)
            # 写限制
            open(f"{CGROUP_PATH}/memory.max", "w").write(memory_limit)
            open(f"{CGROUP_PATH}/cpu.max",    "w").write(f"{cpu_quota} 100000")
            open(f"{CGROUP_PATH}/pids.max",   "w").write(str(pids_max))
            print(f"[CGROUP:v2] Created {CGROUP_PATH}, limits set")
            return CGROUP_PATH
        except PermissionError:
            print("[CGROUP] unified v2 read-only or no permission, falling back to v1")
        except FileNotFoundError:
            print("[CGROUP] unified v2 missing control files, falling back to v1")
        except Exception as e:
            print(f"[CGROUP] v2 setup error: {e}, falling back to v1")

    # 2) 降级到 cgroup v1：分别在 /sys/fs/cgroup/{memory,cpu,pids} 下创建子 cgroup
    v1_paths = {}
    for ctrl, limit_file, val in [
        ("memory", "memory.limit_in_bytes", memory_limit),
        ("cpu",    "cpu.cfs_quota_us",      str(cpu_quota)),
        ("pids",   "pids.max",              str(pids_max)),
    ]:
        base = f"/sys/fs/cgroup/{ctrl}"
        if not os.path.isdir(base):
            print(f"[CGROUP:v1] {ctrl} not mounted, skipping")
            continue
        path = f"{base}/{cgroup_name}"
        try:
            os.makedirs(path, exist_ok=True)
            open(f"{path}/{limit_file}", "w").write(val)
            print(f"[CGROUP:v1] {ctrl} cgroup at {path}, set {limit_file}={val}")
            v1_paths[ctrl] = path
        except Exception as e:
            print(f"[CGROUP:v1] Failed to setup {ctrl} at {path}: {e}")

    if v1_paths:
        CGROUP_PATH = v1_paths
        return v1_paths

    print("[CGROUP] No cgroup could be configured")
    return None

def add_process_to_cgroup(pid):
    """
    将 PID 添加到之前 setup_cgroup 返回的 cgroup。
    - 对于 v2：CGROUP_PATH 是字符串，直接写到 cgroup.procs
    - 对于 v1：CGROUP_PATH 是 dict，需要对每个子系统写入 cgroup.procs
    """
    global CGROUP_PATH

    if not CGROUP_PATH:
        print("[WARNING] cgroup not initialized")
        return False

    # v2 分支
    if isinstance(CGROUP_PATH, str):
        try:
            open(f"{CGROUP_PATH}/cgroup.procs", "w").write(str(pid))
            print(f"[CGROUP:v2] Added PID {pid}")
            return True
        except Exception as e:
            print(f"[CGROUP:v2] Failed to add PID {pid}: {e}")
            return False

    # v1 分支
    success = False
    for ctrl, path in CGROUP_PATH.items():
        try:
            open(f"{path}/cgroup.procs", "w").write(str(pid))
            print(f"[CGROUP:v1] Added PID {pid} to {ctrl}")
            success = True
        except Exception as e:
            print(f"[CGROUP:v1] Failed to add PID {pid} to {ctrl} at {path}: {e}")
    return success

def launch_qemu_in_cgroup(qemu_cmd, cgroup_path, max_procs=30):
    """
    在 cgroup 中启动 QEMU 进程 - 修改版
    """
    global QEMU_PROCESS
    
    # 直接启动 QEMU
    try:
        QEMU_PROCESS = subprocess.Popen(
            qemu_cmd,
            preexec_fn=lambda: limit_procs(max_procs),
            stdout=None,
            stderr=None
        )
        
        print(f"[QEMU] Started QEMU with PID: {QEMU_PROCESS.pid}, max_procs={max_procs}")
        
        # 启动后将进程加入 cgroup
        if cgroup_path and cgroup_path != "systemd":
            time.sleep(0.1)  # 等待进程完全启动
            add_process_to_cgroup(QEMU_PROCESS.pid)
        
        return QEMU_PROCESS
        
    except Exception as e:
        print(f"[ERROR] Failed to launch QEMU: {e}")
        return None

def terminate_cgroup():
    """
    终止 cgroup 中的所有进程，支持 v2 (单一路径) 与 v1 (dict 多路径)。
    """
    if not CGROUP_PATH:
        print("[WARNING] cgroup not initialized")
        return

    # 构建所有可能的 cgroup.procs 路径
    procs_files = []
    if isinstance(CGROUP_PATH, dict):
        # v1: 只关心 pids 子系统
        p = CGROUP_PATH.get('pids')
        if p:
            procs_files.append(os.path.join(p, 'cgroup.procs'))
    else:
        # v2: 单一路径
        procs_files.append(os.path.join(CGROUP_PATH, 'cgroup.procs'))

    for procs in procs_files:
        if os.path.exists(procs):
            try:
                with open(procs) as f:
                    pids = [int(l) for l in f if l.strip()]
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                print(f"[CGROUP] Killed all PIDs in {procs}")
                if QEMU_PROCESS:
                    ret = QEMU_PROCESS.poll()
                    if ret is not None:
                        print(f"[INFO] QEMU exited with code {ret}")
                    else:
                        print("[WARN] QEMU is still running!")
                return
                
            except Exception as e:
                print(f"[CGROUP] Error reading {procs}: {e}")

    print(f"[CGROUP] cgroup.procs not found under {procs_files}, skipping termination")

def cleanup_cgroup():
    """
    清理 cgroup 目录，支持 v2 与 v1，在删除前再次 terminate，再给 Kernel 一点时间，
    然后对 ENOENT, EROFS, EBUSY 三类错误静默跳过，其他错误才打印警告。
    """
    if not CGROUP_PATH:
        return

    # 1) 再次杀掉所有剩余进程
    terminate_cgroup()
    # 2) 等一小会儿让 kernel 收回 cgroup 引用
    time.sleep(0.005)

    # 收集要删除的路径
    dirs = []
    if isinstance(CGROUP_PATH, dict):
        # v1: memory, cpu, pids 各子系统目录
        dirs = list(CGROUP_PATH.values())
    else:
        # v2: 单一路径
        dirs = [CGROUP_PATH]

    for d in dirs:
        try:
            os.rmdir(d)
            print(f"[CGROUP] Removed cgroup: {d}")
        except OSError as e:
            # 仅对非 ENOENT/EROFS/EBUSY 错误打印警告
            if e.errno not in (errno.ENOENT, errno.EROFS, errno.EBUSY):
                print(f"[WARNING] Failed to cleanup cgroup {d}: {e}")
            # Busy 或者 只读/不存在 的都跳过不报错

def monitor_cgroup_resources():
    """
    监控 cgroup 资源使用情况（可在后台线程中运行）
    """
    if not CGROUP_PATH:
        return False

    # v2: CGROUP_PATH 是字符串
    if isinstance(CGROUP_PATH, str):
        memfile = os.path.join(CGROUP_PATH, "memory.current")
        pidfile = os.path.join(CGROUP_PATH, "pids.current")
    # v1: CGROUP_PATH 是 dict，包含各子系统路径
    else:
        memfile = os.path.join(CGROUP_PATH['memory'], "memory.usage_in_bytes")
        pidfile = os.path.join(CGROUP_PATH['pids'], "pids.current")

    mem_ok = os.path.exists(memfile)
    pid_ok = os.path.exists(pidfile)

    # 文件都不存在时，只警告一次，之后仍然保持监控开启
    if not mem_ok and not pid_ok:
        if not hasattr(monitor_cgroup_resources, "_warned"):
            print(f"[CGROUP] No resource files under {CGROUP_PATH}, skipping this check")
            monitor_cgroup_resources._warned = True
        return False

    try:
        stats = []
        if mem_ok:
            with open(memfile, 'r') as f:
                usage = int(f.read().strip())
            stats.append(f"Mem={usage//1024//1024}MB")
        if pid_ok:
            with open(pidfile, 'r') as f:
                pcount = int(f.read().strip())
            stats.append(f"PIDs={pcount}")

        print(f"[CGROUP STATS] {' '.join(stats)}")

        # 检测 fork bomb
        if pid_ok and pcount > 500:
            print("[WARNING] Possible fork bomb in cgroup!")
            return True

    except Exception as e:
        print(f"[ERROR] monitor_cgroup_resources error: {e}")

    return False

def run_analyzer(analyzer_script, data):
    """Run an individual analyzer script and return its result."""
    try:
        result = subprocess.run(
            ['python3', analyzer_script],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            timeout=5
        )
        output = result.stdout.strip()
        if not output:
            return
        result_dict = json.loads(output)
        result_dict["analyzer"] = analyzer_script
        if result.stderr:
            print(f"Analyzer stderr ({analyzer_script}): {result.stderr}")
        return result_dict
    except json.JSONDecodeError as e:
        return {"level": -1, "description": f"Analyzer JSON error: {str(e)}", "analyzer": analyzer_script}
    except subprocess.TimeoutExpired:
        return {"level": -1, "description": f"Analyzer {analyzer_script} timed out", "analyzer": analyzer_script}
    except Exception as e:
        return {"level": -1, "description": f"Error: {str(e)}", "analyzer": analyzer_script}

def safe_terminate(pid, report_lines):
    """
    Try to terminate the given PID (and its process group).  
    Append status messages into report_lines.
    
    修改：如果启用了 cgroup，使用 terminate_cgroup() 终止所有进程
    """
    print("[Alert] Safe_terminate start")
    # ========== 修改：如果使用 cgroup，终止整个 cgroup ==========
    if CGROUP_PATH:
        report_lines.append(f"[CGROUP] Terminating all processes in cgroup due to high risk")
        terminate_cgroup()
        return True
    
    # 原有的终止逻辑
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGTERM)
        report_lines.append(f"Sent SIGTERM to process group {pgid} (PID {pid}).")
        return True
    except ProcessLookupError:
        report_lines.append(f"Could not get pgid for PID {pid}; it may be hidden.")
        hidden_failures.add(pid)
        return False
    except PermissionError as e:
        report_lines.append(f"Permission denied killing PID {pid}: {e}")
        hidden_failures.add(pid)
        return False
    except Exception:
        # Fallback: record failure
        report_lines.append(f"Unknown error terminating PID {pid}.")
        hidden_failures.add(pid)
        return False

def generate_report(results, exe_name):
    """Generate a report and handle high-risk vulnerabilities."""
    valid = [r for r in (results or []) if r is not None]
    # 如果过滤后列表空，就直接返回，不打印任何东西
    if not valid:
        return
    report = [f"Vulnerability Report - {exe_name}"]
    report.append("-" * 50)
    
    high_risk_pids = []
    for result in valid:  # 使用 valid 而不是 results
        if not result:
            continue
        level = result.get("level", 0)
        cvss_vector = result.get("cvss_vector", "Unknown")
        desc = result.get("description", "No description")
        analyzer = result.get("analyzer", "Unknown")
        pid = result.get("pid")
        evidence = result.get("evidence", "No evidence")
        report.append(f"Analyzer: {analyzer}")
        report.append(f"Level: {level}")
        report.append(f"CVSS Vector: {cvss_vector}")
        report.append(f"Description: {desc}")
        if evidence != "No evidence":
            report.append(f"Evidence: {evidence}")
        if pid and pid != 0:
            try:
                pid = int(pid)
                # 先检查进程是否存在
                os.kill(pid, 0)
                print(f"[DEBUG] Process {pid} exists")
                pgid = os.getpgid(pid)
                print(f"[DEBUG] Got PGID {pgid} for PID {pid}")
                seen_pids.add(pgid)
            except ProcessLookupError:
                print(f"[DEBUG] Process {pid} not found")
            except PermissionError as e:
                print(f"[DEBUG] Permission denied for PID {pid}: {e}")
            except Exception as e:
                print(f"[DEBUG] Unexpected error for PID {pid}: {e}")
        
        if level >= HIGH_VULNERABILITY_THRESHOLD and pid > 0:
            high_risk_pids.append(pid)
    
    for pid in high_risk_pids:
        safe_terminate(pid, report)

    return "\n".join(report)













def run_executable_monitoring(executable_info, args, auto_isolate):
    """
    监控单个可执行文件的运行 (V2 - 包含完整的生命周期管理和管道排空逻辑)
    """
    global QEMU_PROCESS, CGROUP_PATH, CGROUP_NAME, CURRENT_EXECUTABLE, seen_pids, hidden_failures
    global EVENT_ANALYZER_MAP, EVT_ANALYZER_MAP, REPORT_GUI_PROCESS
    
    # 重置状态
    QEMU_PROCESS = None
    monitor_process = None # monitor.bt 进程句柄
    seen_pids = set()
    hidden_failures = set()
    CURRENT_EXECUTABLE = executable_info['filename']
    
    print(f"\n{'='*80}")
    print(f"[MONITOR] Starting analysis of: {executable_info['filename']}")
    print(f"[MONITOR] Architecture: {executable_info['architecture']}")
    print(f"[MONITOR] Using QEMU: {executable_info['qemu_command']}")
    print(f"{'='*80}\n")

    try:
        print("[MONITOR] Launching monitor.bt for this session...")
        monitor_process = subprocess.Popen(
            ['bpftrace', 'monitor.bt'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        time.sleep(1) # 等待 bpftrace 就绪
    except Exception as e:
        print(f"[ERROR] Failed to launch monitor.bt: {e}")
        return

    def _process_json_line(line, executor):
        CONTROL_CHAR_RGX = re.compile(r'[\x00-\x1f]+')
        line = CONTROL_CHAR_RGX.sub('', line)
        try:
            data = json.loads(line)
            print(f"[DEBUG] Processing JSON data: {data}")
            if not data: return
            
            data['executable'] = executable_info['filename']
            pid, pre_pid, parent_pid, child_pid = data.get("pid"), data.get("prev_pid"), data.get("parent"), data.get("child")
            for p in [parent_pid, child_pid, pre_pid, pid]:
                if p and p != 0:
                    try: seen_pids.add(os.getpgid(p))
                    except ProcessLookupError: pass
            
            event_type, evt_type = data.get("event"), data.get("evt")
            target_analyzers = EVENT_ANALYZER_MAP.get(event_type, []) + EVT_ANALYZER_MAP.get(evt_type, [])
            
            if not target_analyzers: return
            
            futures = [executor.submit(run_analyzer, script, data) for script in target_analyzers]
            results = [future.result() for future in futures]
            if not results: return
            
            report = generate_report(results, executable_info['filename'])
            if not report: return

            # 发送报告到 GUI
            if REPORT_GUI_PROCESS and REPORT_GUI_PROCESS.poll() is None:
                try:
                    REPORT_GUI_PROCESS.stdin.write(report + "\n" + "="*50 + "\n")
                    REPORT_GUI_PROCESS.stdin.flush()
                except (IOError, BrokenPipeError):
                    print("[WARNING] Report GUI window was closed.")
                    # 声明 nonlocal 或 global 以便修改
                    # global REPORT_GUI_PROCESS 
                    # REPORT_GUI_PROCESS = None
            else:
                print(report); print("=" * 50)
        except json.JSONDecodeError:
            # print(f"[DEBUG] Skipping non-JSON line from bpftrace: {line.strip()}")
            return

    # --- QEMU和cgroup的启动逻辑 (保持不变) ---
    qemu_cmd = [executable_info['qemu_command'], executable_info['filepath']]
    if args.cgroup:
        if CGROUP_PATH: cleanup_cgroup(); CGROUP_PATH = None
        CGROUP_NAME = f"qemu_monitor_{executable_info['filename']}_{uuid.uuid4().hex[:8]}"
        cgroup_path = setup_cgroup(CGROUP_NAME, memory_limit=args.memory_limit, cpu_quota=args.cpu_quota, pids_max=args.pids_max)
        if not cgroup_path: print(f"[ERROR] Failed to setup cgroup, skipping"); return
        QEMU_PROCESS = launch_qemu_in_cgroup(qemu_cmd, cgroup_path, args.fork_max)
        if not QEMU_PROCESS: print(f"[ERROR] Failed to launch QEMU"); cleanup_cgroup(); return
        monitor_stop = threading.Event()
        def monitor_thread():
            while not monitor_stop.is_set() and QEMU_PROCESS and QEMU_PROCESS.poll() is None:
                if monitor_cgroup_resources(): print("[ALERT] Abnormal resource usage!"); terminate_cgroup(); break
                monitor_stop.wait(5)
        monitor = threading.Thread(target=monitor_thread, daemon=True); monitor.start()
    else:
        try:
            QEMU_PROCESS = subprocess.Popen(qemu_cmd, stdout=None, stderr=None)
            print(f"[QEMU] Started QEMU with PID: {QEMU_PROCESS.pid}")
        except Exception as e: print(f"[ERROR] Failed to launch QEMU: {e}"); return
    # --- QEMU启动逻辑结束 ---

    with ThreadPoolExecutor(max_workers=10) as executor:
        try:
            buffer = ""
            brace_count = 0
            qemu_exited = False
            exit_time = None
            grace_period = 1.0
            start_time = time.time()
            timeout = args.timeout

            # --- 主监控循环 (逻辑不变) ---
            while True:
                if time.time() - start_time > timeout: print(f"[TIMEOUT] Execution timeout for {CURRENT_EXECUTABLE}"); break
                if (not qemu_exited) and QEMU_PROCESS and QEMU_PROCESS.poll() is not None:
                    qemu_exited = True; exit_time = time.time(); print(f"[INFO] QEMU exited with code {QEMU_PROCESS.poll()}, entering grace period…")
                if qemu_exited and (time.time() - exit_time) > grace_period: break
                readable, _, _ = select.select([monitor_process.stdout], [], [], 0.7)
                if not readable: continue
                try:
                    raw = monitor_process.stdout.readline();
                    if raw == "": break
                except IOError: continue
                
                if isinstance(raw, bytes): chunk = raw.decode('utf-8', errors='ignore')
                else: chunk = raw
                
                for ch in chunk:
                    if ch == "{":
                        if brace_count == 0: buffer = ""
                        brace_count += 1
                    if brace_count > 0: buffer += ch
                    if ch == "}":
                        brace_count -= 1
                        if brace_count == 0: _process_json_line(buffer, executor); buffer = ""
            
            # ========== 步骤2: 增加“排空管道”阶段 ==========
            print("[MONITOR] Main loop finished. Draining final output from monitor.bt...")
            
            # 温柔地请求 monitor.bt 终止，它会开始关闭并排空自己的缓冲区
            monitor_process.terminate() 
            
            # 循环读取管道中所有剩下的数据，直到管道被bpftrace关闭(EOF)
            for final_line in monitor_process.stdout:
                # 复用相同的处理逻辑
                # 再次用大括号逻辑处理，以防最后的数据不完整
                for ch in final_line:
                    if ch == "{":
                        if brace_count == 0: buffer = ""
                        brace_count += 1
                    if brace_count > 0: buffer += ch
                    if ch == "}":
                        brace_count -= 1
                        if brace_count == 0: _process_json_line(buffer, executor); buffer = ""

            print("[MONITOR] Pipe drained. Analysis for this executable is complete.")

        except KeyboardInterrupt:
            print(f"\n[INTERRUPTED] Stopping analysis of {executable_info['filename']}")
        
        finally:
            # --- 清理逻辑 (现在也管理 monitor_process) ---
            if QEMU_PROCESS and QEMU_PROCESS.poll() is None:
                QEMU_PROCESS.kill() # 使用kill确保退出
            
            if monitor_process and monitor_process.poll() is None:
                monitor_process.kill() # 确保bpftrace也被终止
            
            if args.cgroup and 'monitor_stop' in locals():
                monitor_stop.set()
            
            if CGROUP_PATH:
                cleanup_cgroup()
                CGROUP_PATH = None


















# def run_executable_monitoring(executable_info, args, auto_isolate, monitor_process):
#     """监控单个可执行文件的运行"""
#     global QEMU_PROCESS, CGROUP_PATH, CGROUP_NAME, CURRENT_EXECUTABLE, seen_pids, hidden_failures
#     global EVENT_ANALYZER_MAP, EVT_ANALYZER_MAP, REPORT_GUI_PROCESS
    
#     # 重置状态
#     QEMU_PROCESS = None
#     seen_pids = set()
#     hidden_failures = set()
#     CURRENT_EXECUTABLE = executable_info['filename']
    
#     print(f"\n{'='*80}")
#     print(f"[MONITOR] Starting analysis of: {executable_info['filename']}")
#     print(f"[MONITOR] Architecture: {executable_info['architecture']}")
#     print(f"[MONITOR] Using QEMU: {executable_info['qemu_command']}")
#     print(f"{'='*80}\n")
    
#     # 构建 QEMU 命令
#     qemu_cmd = [executable_info['qemu_command'], executable_info['filepath']]
    
#     # 如果启用了 cgroup，为每个可执行文件创建新的 cgroup
#     if args.cgroup:
#         # 清理之前的 cgroup
#         if CGROUP_PATH:
#             cleanup_cgroup()
#             CGROUP_PATH = None
        
#         # 创建新的 cgroup
#         CGROUP_NAME = f"qemu_monitor_{executable_info['filename']}_{uuid.uuid4().hex[:8]}"
#         cgroup_path = setup_cgroup(
#             CGROUP_NAME,
#             memory_limit=args.memory_limit,
#             cpu_quota=args.cpu_quota,
#             pids_max=args.pids_max
#         )
        
#         if not cgroup_path:
#             print(f"[ERROR] Failed to setup cgroup for {executable_info['filename']}, skipping")
#             return
        
#         # 启动 QEMU
#         qemu_process = launch_qemu_in_cgroup(qemu_cmd, cgroup_path, args.fork_max)
#         if not qemu_process:
#             print(f"[ERROR] Failed to launch QEMU for {executable_info['filename']}")
#             cleanup_cgroup()
#             return
        
#         # 启动资源监控线程
#         monitor_stop = threading.Event()
#         def monitor_thread():
#             while not monitor_stop.is_set() and QEMU_PROCESS and QEMU_PROCESS.poll() is None:
#                 if monitor_cgroup_resources():
#                     print("[ALERT] Abnormal resource usage detected!")
#                     terminate_cgroup()
#                     break
#                 monitor_stop.wait(5)
        
#         monitor = threading.Thread(target=monitor_thread, daemon=True)
#         monitor.start()
#     else:
#         # 不使用 cgroup，直接启动
#         try:
#             QEMU_PROCESS = subprocess.Popen(
#                 qemu_cmd,
#                 stdout=None,
#                 stderr=None
#             )
#             print(f"[QEMU] Started QEMU with PID: {QEMU_PROCESS.pid}")
#         except Exception as e:
#             print(f"[ERROR] Failed to launch QEMU for {executable_info['filename']}: {e}")
#             return
    
#     # 监控循环
#     CONTROL_CHAR_RGX = re.compile(r'[\x00-\x1f]+')
#     with ThreadPoolExecutor(max_workers=10) as executor:
#         try:
#             buffer      = ""
#             brace_count = 0
#             qemu_exited = False
#             exit_time   = None
#             grace_period = 1.0  # 1 秒缓冲期

#             start_time = time.time()
#             timeout    = args.timeout

#             while True:
#                 if time.time() - start_time > timeout:
#                     print(f"[TIMEOUT] Execution timeout for {CURRENT_EXECUTABLE}")
#                     break
                
#                 # 2) 检查 QEMU 是否退出
#                 if (not qemu_exited) and QEMU_PROCESS and QEMU_PROCESS.poll() is not None:
#                     qemu_exited = True
#                     exit_time   = time.time()
#                     print(f"[INFO] QEMU exited with code {QEMU_PROCESS.poll()}, entering grace period…")
                
#                 # 3) 如果已经过了缓冲期，就退出循环
#                 if qemu_exited and (time.time() - exit_time) > grace_period:
#                     print("[DEBUG] Grace period elapsed, breaking monitor loop")
#                     break
                
#                 # 4) 使用 select 检查是否有数据可读，超时时间设为 0.1 秒
#                 readable, _, _ = select.select([monitor_process.stdout], [], [], 0.7)
                
#                 if not readable:
#                     # 没有数据可读，继续循环
#                     continue
                
#                 # 5) 读取数据（非阻塞）
#                 try:
#                     raw = monitor_process.stdout.readline()
#                     if raw == "":  # bpftrace 进程自己结束
#                         print("[DEBUG] monitor.bt EOF")
#                         break
#                 except IOError:
#                     # 没有数据，继续
#                     continue
              
#                 if isinstance(raw, bytes):
#                     chunk = raw.decode('utf-8', errors='ignore')
#                 else:
#                     chunk = raw
                
#                 for ch in chunk:
#                     if ch == "{":
#                         if brace_count == 0:
#                             buffer = ""
#                         brace_count += 1
                    
#                     if brace_count > 0:
#                         buffer += ch
                    
#                     if ch == "}":
#                         brace_count -= 1
#                         if brace_count == 0:
#                             line = buffer.strip()
#                             buffer = ""
#                             line = CONTROL_CHAR_RGX.sub('', line)
                            
#                             try:
#                                 data = json.loads(line)
#                                 if data:
#                                     # 添加当前可执行文件信息
#                                     data['executable'] = executable_info['filename']
                                    
#                                     # 处理 PID 信息
#                                     pid = data.get("pid")
#                                     pre_pid = data.get("prev_pid")
#                                     parent_pid = data.get("parent")
#                                     child_pid = data.get("child")
                                    
#                                     # 收集所有相关的 PID
#                                     for p in [parent_pid, child_pid, pre_pid, pid]:
#                                         if p and p != 0:
#                                             try:
#                                                 pg = os.getpgid(p)
#                                                 seen_pids.add(pg)
#                                             except ProcessLookupError:
#                                                 pass
                                    
#                                     # 获取事件类型
#                                     event_type = data.get("event")
#                                     evt_type = data.get("evt")
#                                     target_analyzers = EVENT_ANALYZER_MAP.get(event_type, [])
#                                     target_analyzers += EVT_ANALYZER_MAP.get(evt_type, [])
                                    
#                                     if not target_analyzers:
#                                         continue
                                    
#                                     # 运行分析器
#                                     futures = [executor.submit(run_analyzer, script, data) 
#                                             for script in target_analyzers]
#                                     results = [future.result() for future in futures]
                                    
#                                     if not results:
#                                         continue
                                    
#                                     report = generate_report(results, executable_info['filename'])
#                                     if not report:
#                                         continue
#                                     # 发送报告到 GUI
#                                     if REPORT_GUI_PROCESS and REPORT_GUI_PROCESS.poll() is None:
#                                         try:
#                                             REPORT_GUI_PROCESS.stdin.write(report + "\n" + "="*50 + "\n")
#                                             REPORT_GUI_PROCESS.stdin.flush()
#                                         except (IOError, BrokenPipeError):
#                                             print("[WARNING] Report GUI window was closed.")
#                                             REPORT_GUI_PROCESS = None
#                                     else:
#                                         print(report)
#                                         print("=" * 50)
                                    
#                                     # 处理隐藏的失败
#                                     if hidden_failures:
#                                         if auto_isolate:
#                                             print("Auto-isolation: terminating ALL seen PIDs.")
#                                             for p in list(seen_pids):
#                                                 try:
#                                                     os.killpg(p, signal.SIGTERM)
#                                                     print(f"Terminated PGID {p}")
#                                                 except Exception as e:
#                                                     print(f"Error terminating PID {p}: {e}")
#                                         else:
#                                             print("Danger! Auto-isolation is off, but some PIDs could not be terminated")
#                                         hidden_failures.clear()
                            
#                             except json.JSONDecodeError as e:
#                                 # 静默跳过无效的 JSON
#                                 continue
        
#         except KeyboardInterrupt:
#             print(f"\n[INTERRUPTED] Stopping analysis of {executable_info['filename']}")
        
#         finally:
#             # 清理进程
#             if QEMU_PROCESS:
#                 QEMU_PROCESS.terminate()
#                 try:
#                     QEMU_PROCESS.wait(timeout=5)
#                 except subprocess.TimeoutExpired:
#                     QEMU_PROCESS.kill()
            
#             # 停止监控线程
#             if args.cgroup and 'monitor_stop' in locals():
#                 monitor_stop.set()
            
#             # 清理 cgroup
#             if CGROUP_PATH:
#                 cleanup_cgroup()
#                 CGROUP_PATH = None



























def main():
    global REPORT_GUI_PROCESS, EVENT_ANALYZER_MAP, EVT_ANALYZER_MAP
    
    # 加载配置
    with cfg_path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    EVENT_ANALYZER_MAP = cfg["EVENT_ANALYZER_MAP"]
    EVT_ANALYZER_MAP = cfg["EVT_ANALYZER_MAP"]
    
    os.system("python3 initial.py")
    
    # 启动报告 GUI
    try:
        REPORT_GUI_PROCESS = subprocess.Popen(
            ['python3', 'report_gui.py'], 
            stdin=subprocess.PIPE, 
            text=True, 
            encoding='utf-8'
        )
        print("Launched vulnerability report window.")
    except Exception as e:
        print(f"[ERROR] Failed to launch report_gui.py: {e}")
        REPORT_GUI_PROCESS = None
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='QEMU Security Monitor with directory scanning')
    parser.add_argument('directory', help='Directory containing executables to analyze')
    parser.add_argument('--cgroup', action='store_true', help='Enable cgroup resource limiting')
    parser.add_argument('--memory-limit', default='2G', help='cgroup memory limit (default: 2G)')
    parser.add_argument('--cpu-quota', type=int, default=200000, help='cgroup CPU quota (default: 200000 = 200%%)')
    parser.add_argument('--pids-max', type=int, default=1000, help='cgroup max processes (default: 1000)')
    parser.add_argument('--fork-max', type=int, default=50, help='max fork (default: 50)')
    parser.add_argument('--timeout', type=int, default=60, help='timeout per executable in seconds (default: 60)')
    
    args = parser.parse_args()
    
    # 询问是否启用自动隔离
    ans = input("Enable auto-isolation of all seen PIDs on hidden failures? [y/N]: ")
    auto_isolate = ans.strip().lower() == 'y'
    
    # 如果启用 cgroup，检查权限
    if args.cgroup and os.geteuid() != 0:
        print("[ERROR] cgroup support requires root privileges")
        print("Please run with sudo")
        return
    
    # 运行架构分析器
    print(f"[SCAN] Analyzing executables in: {args.directory}")
    try:
        result = subprocess.run(
            ['python3', 'arch_analyzer.py', args.directory],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"[ERROR] Architecture analyzer failed: {result.stderr}")
            return
        
        executables = json.loads(result.stdout)
        
        if not executables:
            print("[INFO] No supported executables found in the directory")
            return
        
        print(f"[SCAN] Found {len(executables)} supported executable(s)")
        
    except Exception as e:
        print(f"[ERROR] Failed to analyze directory: {e}")
        return
    
    print(f"[SCAN] Found {len(executables)} supported executable(s)")

    try:
        # 串行运行每个可执行文件
        for i, executable in enumerate(executables, 1):
            print(f"\n[PROGRESS] Processing {i}/{len(executables)}: {executable['filename']}")

            # —— 每次启动独立的 bpftrace 监控器 —— 
            # monitor_process = subprocess.Popen(
            #     ['bpftrace', 'monitor.bt'],
            #     stdout=subprocess.PIPE,
            #     stderr=subprocess.STDOUT,
            #     text=True,
            #     encoding='utf-8',
            #     errors='replace'
            # )
            # 等待 bpftrace 脚本就绪
            # time.sleep(1)

            # 传入这次的 monitor_process，跑分析
            # run_executable_monitoring(executable, args, auto_isolate, monitor_process)

            # 跑完之后立刻关闭本次的监控
            # monitor_process.terminate()
            # monitor_process.wait()
            # print("[MONITOR] monitor.bt terminated for this executable.")
            run_executable_monitoring(executable, args, auto_isolate)
            time.sleep(0.01)  
        print("Would you like to exit the wrapper? [y/N]: ")
        if input().strip().lower() == 'y':
            print("Exiting wrapper...")
            return
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Analysis interrupted by user")
    
    finally:
        # 清理
        # monitor_process.terminate()
        print("Monitor terminated.")
        
        if REPORT_GUI_PROCESS:
            print("Terminating report window...")
            REPORT_GUI_PROCESS.terminate()

if __name__ == "__main__":
    main()