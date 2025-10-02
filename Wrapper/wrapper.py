#!/usr/bin/env -S python3

import subprocess, json, os, argparse, signal, re, threading, uuid, time, errno, select, resource
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Optional docker integration
try:
    from docker_integration import DockerRunner  # type: ignore
    _DOCKER_OK = True
except Exception:
    _DOCKER_OK = False
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
    # Try cgroup v2 first
    v2_mount = None
    try:
        with open("/proc/mounts") as m:
            for line in m:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "cgroup2":
                    v2_mount = parts[1]
                    break
    except Exception as e:
        print(f"[CGROUP] Failed reading /proc/mounts: {e}")

    if v2_mount:
        path = f"{v2_mount}/{cgroup_name}"
        try:
            os.makedirs(path, exist_ok=True)
            # Set limits if possible (ignore failures silently)
            def _w(p, val):
                try:
                    open(p, 'w').write(val)
                except Exception:
                    pass
            # memory
            _w(f"{path}/memory.max", memory_limit)
            # cpu (quota/period) - approximate: use 100000 period
            if cpu_quota > 0:
                _w(f"{path}/cpu.max", f"{cpu_quota} 100000")
            # pids
            _w(f"{path}/pids.max", str(pids_max))
            CGROUP_PATH = path
            print(f"[CGROUP:v2] Created {path}")
            return path
        except Exception as e:
            print(f"[CGROUP:v2] Failed to setup {path}: {e}; falling back to v1")

    # Fallback to cgroup v1 controllers
    v1_paths = {}
    controllers = [
        ("memory", "memory.limit_in_bytes", memory_limit),
        ("cpu",    "cpu.cfs_quota_us",      str(cpu_quota)),
        ("pids",   "pids.max",              str(pids_max)),
    ]
    for ctrl, limit_file, val in controllers:
        base = f"/sys/fs/cgroup/{ctrl}"
        if not os.path.isdir(base):
            continue
        path = f"{base}/{cgroup_name}"
        try:
            os.makedirs(path, exist_ok=True)
            open(f"{path}/{limit_file}", 'w').write(val)
            v1_paths[ctrl] = path
            print(f"[CGROUP:v1] {ctrl} -> {path} ({limit_file}={val})")
        except Exception as e:
            print(f"[CGROUP:v1] Failed to setup {ctrl}: {e}")

    if v1_paths:
        CGROUP_PATH = v1_paths
        return v1_paths

    print("[CGROUP] Could not configure any cgroup")
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


_CACHED_CGROUPID_SUPPORT = None

def _detect_cgroupid_support() -> bool:
    """Detect if current bpftrace supports the 'cgroupid' builtin.
    Old logic falsely returned False because bpftrace never exits on its own.
    New strategy: spawn a tiny bpftrace program referencing cgroupid, wait until it prints 'Attaching',
    then terminate. If we see a syntax error line -> unsupported.
    Cached after first determination.
    """
    global _CACHED_CGROUPID_SUPPORT
    if _CACHED_CGROUPID_SUPPORT is not None:
        return _CACHED_CGROUPID_SUPPORT
    # Must be root (unless user configured capabilities) – if not, treat as unsupported so we fallback gracefully
    if os.geteuid() != 0:
        _CACHED_CGROUPID_SUPPORT = False
        return _CACHED_CGROUPID_SUPPORT
    try:
        proc = subprocess.Popen(
            ['bpftrace', '-e', 'tracepoint:syscalls:sys_enter_execve / cgroupid >= 0 / { exit(); }'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace'
        )
        supported = False
        start = time.time()
        # Read a few lines (up to 1.5s) looking for either attach or syntax error
        while time.time() - start < 1.5 and proc.poll() is None:
            if not proc.stdout:
                break
            if select.select([proc.stdout], [], [], 0.3)[0]:
                line = proc.stdout.readline()
                if not line:
                    break
                l = line.lower()
                if 'syntax error' in l or 'unknown' in l:
                    supported = False
                    break
                if 'attaching' in l:
                    # If it managed to attach, parsing succeeded; execve may not happen before timeout
                    supported = True
        # Ensure process terminated
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=0.5)
            except Exception:
                proc.kill()
        _CACHED_CGROUPID_SUPPORT = supported
    except Exception:
        _CACHED_CGROUPID_SUPPORT = False
    return _CACHED_CGROUPID_SUPPORT

def _generate_docker_monitor_script(container_pid: int, target_comm: str, want_cgroup: bool, force_cgroup: bool) -> str:
    """Generate docker monitor script.
    If want_cgroup and bpftrace supports cgroupid builtin and cgroup inode resolves -> use cgroup filter.
    Else fallback to pid + prefix strategy.
    """
    base_script = Path('monitor.bt').read_text(encoding='utf-8')
    prefix = target_comm[:15]
    use_cgroup = False
    cgid = None
    if (want_cgroup or force_cgroup) and container_pid > 0 and (force_cgroup or _detect_cgroupid_support()):
        # Try resolve cgroup v2 inode
        try:
            with open(f"/proc/{container_pid}/cgroup", 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) == 3 and parts[0] == '0':
                        rel = parts[2].lstrip('/')
                        cpath = f"/sys/fs/cgroup/{rel}"
                        if os.path.isdir(cpath):
                            try:
                                cgid = os.stat(cpath).st_ino
                                use_cgroup = cgid is not None
                            except Exception:
                                use_cgroup = False
                        break
        except Exception:
            use_cgroup = False

    injected: list[str] = ["// === Dynamic docker monitor script ==="]
    if use_cgroup and cgid is not None:
        print(f"[DOCKER][CGROUP] Using cgroupid filter (inode={cgid}) for container PID {container_pid}")
        injected += [
            f"// cgroup mode enabled (inode {cgid})",
            f"#define TARGET_CGID {cgid}",
            # Exec mark + track
            "tracepoint:sched:sched_process_exec / cgroupid == TARGET_CGID / { @monitored[pid]=1; printf(\"{\\\"ts\\\":%llu,\\\"event\\\":\\\"TRACK_DOCKER_BIN\\\",\\\"pid\\\":%d,\\\"bin\\\":\\\"%s\\\"}\\n\", nsecs/1000000000ULL, pid, comm); }",
            # Process tree expansion (child inherits monitoring if parent already monitored)
            "tracepoint:sched:sched_process_fork / @monitored[args->parent_pid] / { @monitored[args->child_pid]=1; }",
            # Early syscall auto mark
            "tracepoint:syscalls:sys_enter_execve   / cgroupid == TARGET_CGID && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_write    / cgroupid == TARGET_CGID && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_read     / cgroupid == TARGET_CGID && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_setuid   / cgroupid == TARGET_CGID && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_mprotect / cgroupid == TARGET_CGID && !@monitored[pid] / { @monitored[pid]=1; }",
            "",
        ]
    else:
        reason = []
        if not want_cgroup and not force_cgroup:
            reason.append('disabled by flag')
        elif container_pid <= 0:
            reason.append('no container pid')
        elif os.geteuid() != 0 and not (force_cgroup and _detect_cgroupid_support()):
            reason.append('need root')
        elif not (force_cgroup or _detect_cgroupid_support()):
            reason.append('bpftrace lacks cgroupid builtin')
        else:
            reason.append('inode resolve failed')
        print(f"[DOCKER][CGROUP] Fallback to prefix mode ({'; '.join(reason)})")
        injected += [
            f"BEGIN {{ @monitored[{container_pid}] = 1; }}",
            f"// fallback prefix '{prefix}' (cgroup mode {'requested but unsupported' if want_cgroup else 'disabled'})",
            "tracepoint:sched:sched_process_exec / strncmp(comm, \"" + prefix + "\", " + str(len(prefix)) + ") == 0 / { @monitored[pid]=1; printf(\"{\\\"ts\\\":%llu,\\\"event\\\":\\\"TRACK_DOCKER_BIN\\\",\\\"pid\\\":%d,\\\"bin\\\":\\\"%s\\\"}\\n\", nsecs/1000000000ULL, pid, comm); }",
            # Process tree expansion: any forked child of a monitored parent becomes monitored
            "tracepoint:sched:sched_process_fork / @monitored[args->parent_pid] / { @monitored[args->child_pid]=1; }",
            "tracepoint:syscalls:sys_enter_execve   / strncmp(comm, \"" + prefix + "\", " + str(len(prefix)) + ") == 0 && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_write    / strncmp(comm, \"" + prefix + "\", " + str(len(prefix)) + ") == 0 && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_read     / strncmp(comm, \"" + prefix + "\", " + str(len(prefix)) + ") == 0 && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_setuid   / strncmp(comm, \"" + prefix + "\", " + str(len(prefix)) + ") == 0 && !@monitored[pid] / { @monitored[pid]=1; }",
            "tracepoint:syscalls:sys_enter_mprotect / strncmp(comm, \"" + prefix + "\", " + str(len(prefix)) + ") == 0 && !@monitored[pid] / { @monitored[pid]=1; }",
            "",
        ]
    script_text = "\n".join(injected) + "\n" + base_script
    tmp_path = Path(f"/tmp/monitor_docker_{container_pid}.bt")
    tmp_path.write_text(script_text, encoding='utf-8')
    return str(tmp_path)


def run_executable_monitoring_docker(executable_info, args, auto_isolate, docker_runner: DockerRunner):
    """Docker mode: run binary inside container & monitor both qemu- (if any) and container PID."""
    filename = executable_info['filename']
    print(f"\n{'='*80}\n[DOCKER] Starting analysis of: {filename}\n[DOCKER] Architecture: {executable_info['architecture']}\n{'='*80}")
    container = None
    container_pid = 0
    exec_deferred = False
    staged_mode = getattr(args, 'docker_staged', True)
    force_qemu = getattr(args, 'docker_force_qemu', False)

    # Always try staged unless user disabled with --no-docker-staged
    if staged_mode:
        print("[DOCKER] Staged mode: launching idle container first")
        container = docker_runner.start_staged_container(executable_info['architecture'])
        if container:
            try:
                container.reload(); container_pid = int(container.attrs.get('State', {}).get('Pid', 0))
            except Exception:
                container_pid = 0
            if not container_pid:
                print("[DOCKER] Warning: staged container PID unresolved; seeding with 0")
            exec_deferred = True
        else:
            print("[DOCKER] Staged start failed; fallback to direct run mode")
            staged_mode = False
    if not staged_mode:
        run_info = docker_runner.run_binary(executable_info['filepath'], executable_info['architecture'])
        if not run_info:
            print("[DOCKER] Failed to start container; skipping")
            return
        container = run_info['container']
        container_pid = run_info.get('pid', 0)
        if not container_pid:
            print("[DOCKER] Could not determine container PID (monitor may be incomplete)")

    # Create dynamic monitor script using container PID (0 tolerated)
    # Determine cgroup usage intention
    want_cgroup = not getattr(args, 'docker_no_cgroup', False)
    force_cgroup = getattr(args, 'docker_force_cgroup', False)
    monitor_script = _generate_docker_monitor_script(container_pid, filename[:12], want_cgroup=want_cgroup, force_cgroup=force_cgroup)
    try:
        monitor_process = subprocess.Popen(
            ['bpftrace', monitor_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
    except Exception as e:
        print(f"[DOCKER] Failed to launch bpftrace: {e}")
        docker_runner.cleanup(container)
        return

    # If staged, wait until we see the "Attaching" line before executing target binary
    attach_seen = False
    if staged_mode:
        attach_deadline = time.time() + 5
        prebuffer = []
        while time.time() < attach_deadline and not attach_seen and monitor_process.stdout:
            r, _, _ = select.select([monitor_process.stdout], [], [], 0.3)
            if not r:
                continue
            line_raw = monitor_process.stdout.readline()
            if line_raw == '':
                break
            prebuffer.append(line_raw)
            if 'Attaching ' in line_raw:
                attach_seen = True
        # Emit prebuffered lines
        for l in prebuffer:
            print(f"[BPF-RAW] {l.strip()}")
        if not attach_seen:
            print('[DOCKER] Warning: did not confirm bpftrace attach before exec; proceeding anyway')

    def _process_line(line, executor):
        try:
            data = json.loads(re.sub(r'[\x00-\x1f]+', '', line))
        except json.JSONDecodeError:
            return
        data['executable'] = filename
        event_type, evt_type = data.get('event'), data.get('evt')
        target_analyzers = EVENT_ANALYZER_MAP.get(event_type, []) + EVT_ANALYZER_MAP.get(evt_type, [])
        if not target_analyzers:
            return
        futures = [executor.submit(run_analyzer, script, data) for script in target_analyzers]
        results = [f.result() for f in futures if f.result()]
        report = generate_report(results, filename)
        if report:
            if REPORT_GUI_PROCESS and REPORT_GUI_PROCESS.poll() is None:
                try:
                    REPORT_GUI_PROCESS.stdin.write(report + "\n" + "="*50 + "\n")
                    REPORT_GUI_PROCESS.stdin.flush()
                except Exception:
                    print(report); print("="*50)
            else:
                print(report); print("="*50)

    start_time = time.time()
    timeout = args.timeout
    buffer = ""; brace = 0
    exec_finished = False
    exec_exit_code = None
    exec_output = ''
    grace_after_exec = 1.5  # seconds to keep draining after exec
    exec_end_time = None
    with ThreadPoolExecutor(max_workers=8) as executor:
        try:
            # If staged: launch exec in background so we don't miss very short-lived syscalls
            exec_thread = None
            exec_state = {"done": False, "code": None, "output": ""}
            if exec_deferred and container is not None:
                print("[DOCKER] Executing target binary inside staged container (async thread)...")
                def _run_exec():
                    nonlocal exec_end_time, exec_exit_code, exec_output, exec_finished
                    res = docker_runner.exec_binary_in_container(
                        container,
                        executable_info['filepath'],
                        force_qemu=force_qemu,
                        arch_info=executable_info['architecture']
                    ) or (-1, "")
                    exec_exit_code_local, exec_output_local = res
                    exec_exit_code = exec_exit_code_local
                    exec_output = exec_output_local
                    exec_finished = True
                    exec_end_time = time.time()
                    exec_state["done"] = True
                    exec_state["code"] = exec_exit_code_local
                    exec_state["output"] = exec_output_local
                exec_thread = threading.Thread(target=_run_exec, daemon=True)
                exec_thread.start()
            while True:
                now = time.time()
                # Global timeout
                if now - start_time > timeout:
                    print(f"[DOCKER] Timeout for {filename}")
                    break
                # Grace period after exec
                if exec_finished and exec_end_time and (now - exec_end_time) > grace_after_exec:
                    break
                r, _, _ = select.select([monitor_process.stdout], [], [], 0.6)
                if not r:
                    # check if container finished and monitor quiet
                    if monitor_process.poll() is not None:
                        break
                    continue
                line_raw = monitor_process.stdout.readline()
                if line_raw:
                    print(f"[BPF-RAW] {line_raw.strip()}")
                if line_raw == "":
                    break
                chunk = line_raw
                for ch in chunk:
                    if ch == '{':
                        if brace == 0:
                            buffer = ''
                        brace += 1
                    if brace > 0:
                        buffer += ch
                    if ch == '}':
                        brace -= 1
                        if brace == 0:
                            _process_line(buffer, executor)
                            buffer = ''
        finally:
            # Join exec thread if still running
            try:
                if 'exec_thread' in locals() and exec_thread and exec_thread.is_alive():
                    exec_thread.join(timeout=0.2)
            except Exception:
                pass
            # In staged mode the container is still sleeping; stop it explicitly after grace
            if staged_mode and container is not None:
                try:
                    container.stop(timeout=2)
                except Exception:
                    pass
            if staged_mode:
                code = exec_exit_code if exec_exit_code is not None else -1
                logs = exec_output
            else:
                code, logs = docker_runner.wait(container, timeout=timeout)
            print(f"[DOCKER] Container exit code: {code}")
            if logs and logs.strip():
                print("[DOCKER] Logs:\n" + logs.rstrip())
            if container is not None:
                docker_runner.cleanup(container)
            if monitor_process and monitor_process.poll() is None:
                monitor_process.terminate()
                try:
                    monitor_process.wait(timeout=2)
                except Exception:
                    monitor_process.kill()
            # remove temp script
            try:
                os.remove(monitor_script)
            except OSError:
                pass




































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
    parser.add_argument('--docker', action='store_true', help='Run binaries inside docker containers (multi-arch)')
    parser.add_argument('--no-docker-staged', action='store_false', dest='docker_staged', default=True,
                        help='Disable staged docker mode (attach bpftrace before exec). Enabled by default.')
    parser.add_argument('--docker-force-qemu', action='store_true', dest='docker_force_qemu',
                        help='Force executing binary via qemu-<arch> inside container even if host arch matches (requires qemu-user in image).')
    parser.add_argument('--docker-no-cgroup', action='store_true', dest='docker_no_cgroup',
                        help='Disable cgroup-wide tracing inside docker (fallback to prefix).')
    parser.add_argument('--docker-force-cgroup', action='store_true', dest='docker_force_cgroup',
                        help='Force cgroup-wide tracing; if unsupported will still fallback, but skip prefix fast path attempt.')
    
    args = parser.parse_args()
    
    # 询问是否启用自动隔离
    ans = input("Enable auto-isolation of all seen PIDs on hidden failures? [y/N]: ")
    auto_isolate = ans.strip().lower() == 'y'
    
    # 如果启用 cgroup，检查权限 (docker 模式下可不需要 root 仅当需要 cgroup 限制才要求)
    if args.cgroup and os.geteuid() != 0 and not args.docker:
        print("[ERROR] cgroup support requires root privileges (non-docker mode)")
        return

    if args.docker and not _DOCKER_OK:
        print("[ERROR] Docker mode requested but docker SDK not available. Install python3-docker.")
        return
    if args.docker and os.geteuid() != 0:
        print("[WARNING] Running docker mode without root: bpftrace may produce no output (permission denied to tracepoints). Consider sudo.")
    
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
        docker_runner = DockerRunner() if args.docker and _DOCKER_OK else None
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
            if args.docker and docker_runner:
                run_executable_monitoring_docker(executable, args, auto_isolate, docker_runner)
            else:
                run_executable_monitoring(executable, args, auto_isolate)
            time.sleep(0.01)
        print("Would you like to exit the wrapper? [y/N]: ")
        try:
            if input().strip().lower() == 'y':
                print("Exiting wrapper...")
                return
        except EOFError:
            pass
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