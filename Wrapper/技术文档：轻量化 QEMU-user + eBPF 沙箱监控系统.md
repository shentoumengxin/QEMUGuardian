# 技术文档：轻量化 QEMU-user + eBPF 沙箱监控系统

以下文档分为两大部分，分别介绍 **monitor.bt**（bpftrace 脚本）的设计和 **wrapper.py**（Python 控制脚本）的设计思路、模块划分、核心流程和关键技术要点。可作为后续论文撰写的技术参考。

------

## 一、monitor.bt 设计

### 1. 设计目标

- **跨平台可重用**：不依赖特定架构，监控所有 `qemu-<arch>` 用户态进程的系统调用和关键行为。
- **低开销**：利用 eBPF tracepoint/kprobe/uprobes，避免全插桩带来的高额开销；
- **高保真**：输出丰富的 JSON 事件，含时间戳、PID、事件类型及必要的元数据；
- **可扩展**：后续可以轻松添加新的 probe（如 `setuid`、`mprotect`、`madvise`）。

### 2. 核心流程

1. **初始化**

   ```bpftrace
   BEGIN {
       printf("{\"ts\":%llu,\"event\":\"START\",\"message\":\"monitor started\"}\n", nsecs/1e9);
   }
   ```

   打印启动事件。

2. **进程标记**

   - 第一次捕获 `sys_enter_openat` 且进程名符合 `qemu-.*` 时，将该 PID 加入监控集 `@monitored`。
   - 捕获 `sched_process_fork`、`sched_process_exec` 事件，保持对子进程、exec 后进程的跟踪。

3. **系统调用探针**

   - **文件操作**：`openat`、`read`、`write`、`readlinkat("/proc/self/cwd")`
   - **网络行为**：`socket`、`connect`、`sendto`、`recvfrom`
   - **进程控制**：`dup2`、`execve`、`wait4`、`sched_switch`、`signal_generate`
   - **安全相关**：`setuid`、`mprotect`、`madvise`

   每个探针格式统一输出：

   ```
   json复制编辑{
     "ts": <浮点秒>,
     "event": "<事件码>",
     // 若需其他字段：pid、fd、len、addr、read/write/exec 标志位等
   }
   ```

4. **内存/分配统计**

   - 通过 `uprobe` 捕获 `malloc`/`calloc`/`realloc`/`free` 的调用次数：
      每秒输出一次 `{ "evt":"ALLOC_SUM"/"FREE_SUM", "count": N }`
   - `mmap` 统计映射总次数和最大页数：
      每秒输出 `{ "evt":"MMAP_SUM","count":X,"max_pages":Y }`

5. **结束**

   ```bpftrace
   END {
     printf("{\"ts\":%llu,\"event\":\"END\",\"message\":\"monitor stopped\"}\n",nsecs/1e9);
   }
   ```

### 3. 输出格式示例

```
jsonc复制编辑{"ts":6523.123456,"event":"TRACK_OPENAT","pid":12345,"bin":"qemu-x86_64","file":"./demo"}
{"ts":6523.234567,"event":"READ","pid":12345,"fd":3,"buf":"GET /index.html"}
{"ts":6523.345678,"event":"SOCKET","pid":12345,"domain":2,"type":1}
{"ts":6523.456789,"evt":"ALLOC_SUM","meta":{"count":42}}
{"ts":6523.567890,"evt":"FREE_SUM","meta":{"count":40}}
{"ts":6523.678901,"evt":"MMAP_SUM","meta":{"count":10,"max_pages":128}}
{"ts":6523.789012,"event":"END","message":"monitor stopped"}
```

------

## 二、wrapper.py 设计

### 1. 设计目标

- **自动化启动**：一条命令完成 cgroup 环境准备、bpftrace 监控与 QEMU-user 沙箱运行；
- **通用分析框架**：将 bpftrace 输出的 JSON 事件分发给可插拔的 Python 分析器（analyzers）；
- **实时报警与响应**：如检测到高危行为（fork bomb、shellcode、命令注入等），可自动终止 QEMU 进程；
- **资源限制**：可选地将 QEMU 进程放入 cgroup，控制内存/CPU/PID 数量。

### 2. 模块划分

```
wrapper.py
├─ 参数解析
│   └─ --qemu-cmd, --cgroup, --memory-limit, --cpu-quota, --pids-max
├─ cgroup 管理（v2 & v1 兼容）
│   ├─ setup_cgroup()
│   ├─ add_process_to_cgroup()
│   ├─ monitor_cgroup_resources()   ← 后台线程
│   ├─ terminate_cgroup()
│   └─ cleanup_cgroup()
├─ QEMU 启动
│   └─ launch_qemu_in_cgroup()
├─ bpftrace 启动
│   └─ subprocess.Popen(['bpftrace','monitor.bt'], ...)
├─ 实时事件分发
│   ├─ 按行读取 stdout，计数 `{`/`}` 与缓冲 JSON
│   ├─ 过滤控制字符 & 非 JSON 行
│   ├─ json.loads → 得到 dict
│   ├─ 根据 `event`/`evt` 字段，映射到对应 analyzer 脚本列表
│   └─ ThreadPoolExecutor 并行调用 run_analyzer()
├─ 报告生成
│   └─ generate_report()：聚合各 analyzer 输出，打印 Vulnerability Report
└─ 清理与退出
    └─ KeyboardInterrupt / 程序结束时清理 cgroup & QEMU 进程
```

### 3. 核心流程

1. **解析命令行**

   ```bash
   sudo python3 wrapper.py --cgroup --qemu-cmd qemu-x86_64 demo
   ```

2. **Cgroup 准备**

   - 尝试在 `/sys/fs/cgroup/unified`（v2）创建子目录；失败则回退到各 v1 子系统
   - 写入 `memory.max`、`cpu.max`、`pids.max`

3. **启动 bpftrace**

   - `Popen(..., stdout=PIPE, stderr=PIPE, text=False)`

4. **启动 QEMU**

   - `Popen(qemu_cmd, stdout=PIPE, stderr=PIPE)`
   - 将 QEMU PID 添加到 cgroup
   - 启动后台线程定期调用 `monitor_cgroup_resources()`，检测 fork bomb／资源异常

5. **事件读取 & 分发**

   - 主线程循环读取 bpftrace stdout，基于花括号计数组装完整 JSON
   - 过滤控制字符后 `json.loads`，拿到 `data` 字典
   - 按 `event` 和 `evt` 字段，从预定义的映射表中选出对应 analyzers
   - 并行调用各分析脚本 `run_analyzer()`，接收 JSON 输出（`level`, `description`, `pid`…）

6. **实时报告 & 响应**

   - `generate_report()` 汇总各分析器结果
   - 若任一 `level >= 高危阈值`，调用 `safe_terminate()`：
     - 若启用 cgroup，则 `terminate_cgroup()`；否则 `killpg(pid)`

7. **退出清理**

   - 捕获 SIGINT/程序自然结束，调用 `cleanup_cgroup()`（终止 & 删除 cgroup）
   - 杀死 QEMU 进程组

### 4. 关键技术要点

- **花括号计数解析**
   由于 bpftrace 输出中可能穿插日志、警告，用计数 `{`/`}` 方法保证只处理完整 JSON 块。
- **控制字符过滤**
   通过正则 `[\x00-\x1f]+` 去除换行、回车、制表符等，防止 JSONDecodeError。
- **并发分析**
   `ThreadPoolExecutor` 让每条事件可并行触发多个分析器，减少时延。
- **cgroup 双模式支持**
  - 优先 v2；若只读或无权限则退到解析 `/proc/self/cgroup`
  - 最后回落到 v1 各子系统（memory/cpu/pids）
- **模块化 & 可扩展**
  - analyzer 脚本仅需满足：读取 stdin JSON → 输出一条 JSON → exit
  - `EVENT_ANALYZER_MAP` 可自由扩展，支持任意新安全检测逻辑

------

## 三、后续扩展与论文写作建议

1. **基于 libbpf CO-RE 重写**
   - 从 bpftrace 迁移到 libbpf+CO-RE，降低脚本开销，提高可移植性；
2. **在内核 LSM 钩子上阻断**
   - 结合 eBPF LSM，在 syscall-entry 拦截非法操作并返回 `EPERM`；
3. **性能评测**
   - 对比 Pin、Valgrind、QEMU-TCG 全翻译：启动延迟、运行吞吐、内存开销；
4. **安全案例**
   - 注入 shellcode、命令注入、fork bomb、勒索软件沙箱化演示；
5. **多容器/多租户场景**
   - 将 wrapper 部署于 Kubernetes Pod，监控容器内部 QEMU 实例；

以上内容可作为论文中“系统设计”、“实现细节”和“评估指标”章节的技术背景与支撑。祝研究顺利！