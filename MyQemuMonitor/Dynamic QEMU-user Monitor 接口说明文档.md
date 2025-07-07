# Dynamic QEMU-user Monitor 接口文档

## 1. 概述

此 bpftrace 脚本用于动态监控以 "qemu-" 开头的进程及其子进程的系统调用和资源使用情况。脚本通过跟踪文件操作、网络活动、内存分配、进程管理和调度等关键事件，输出 JSON 格式的数据，便于分析和调试。

## 2. 功能特性

- **进程监控**：跟踪以 "qemu-" 开头的进程及其通过 `fork`/`clone`/`vfork` 创建的子进程。
- **系统调用跟踪**：捕获文件操作（`openat`、`read`、`write`）、网络操作（`socket`、`connect`、`sendto`、`recvfrom`）、文件描述符管理（`dup2`）、进程等待（`wait4`）等。
- **资源使用统计**：监控内存分配（`malloc`、`calloc`、`realloc`、`free`）和内存映射（`mmap`）的调用次数及最大页面数。
- **调度和信号**：捕获上下文切换和信号生成事件。
- **事件输出**：以 JSON 格式输出，包含时间戳、事件类型和相关参数。

## 3. 事件输出格式

所有事件均为 JSON 格式，通用字段包括：

- `ts`：时间戳（秒，自系统启动）。 

  😍😍**经过我的测试应该是从命令行启用开始。是一个相对时间，如要使用请注意**

- `event`：事件类型。

- pid：进程 ID（统计事件中为 -1）。

- 其他字段：根据事件类型变化。

### 3.1 监控启停

- START：脚本启动。

  ```json
  {"ts":<timestamp>,"event":"START","message":"Dynamic QEMU-user monitor started"}
  ```

- END：脚本结束。

  ```json
  {"ts":<timestamp>,"event":"END","message":"Dynamic QEMU-user monitor stopped"}
  ```

### 3.2 进程跟踪

- TRACK_OPENAT：以 "qemu-" 开头的进程调用 openat，加入监控。

  ```json
  {"ts":<timestamp>,"event":"TRACK_OPENAT","pid":<pid>,"bin":"<binary_name>","file":"<filename>"}
  ```

- TRACK_FORK：监控进程创建子进程，子进程加入监控。

  ```json
  {"ts":<timestamp>,"event":"TRACK_FORK","parent":<parent_pid>,"child":<child_pid>}
  ```

- EXEC：监控进程调用 execve

  ```json
  {"ts":<timestamp>,"event":"EXEC","pid":<pid>,"filename":"<executed_file>"}
  ```

😍**这里注意可以从filename观察到qemu切换成了那个程序！**

### 3.3 系统调用

- READ

  ```json
  {"ts":<timestamp>,"event":"READ","pid":<pid>,"fd":<file_descriptor>,"buf":"<buffer_content>"}
  ```

- WRITE

  ```json
  {"ts":<timestamp>,"event":"WRITE","pid":<pid>,"fd":<file_descriptor>,"buf":"<buffer_content>"}
  ```

  😍**注意这里buf是可以看到缓存区中的具体内容的，可以对内容进行具体分析，例如{"ts":7859,"event": "READ", "pid": 25518, "fd": 0, "buf": "pwd"} 但这里要注意一下输入自带换行符\n**

- READLINKAT

  ```
  /proc/self/cwd
  ```

  ```json
  {"ts":<timestamp>,"event":"READLINKAT","pid":<pid>,"path":"/proc/self/cwd"}
  ```

- SOCKET

  ```json
  {"ts":<timestamp>,"event":"SOCKET","pid":<pid>,"domain":<domain>,"type":<type>}
  ```

- CONNECT

  ```json
  {"ts":<timestamp>,"event":"CONNECT","pid":<pid>,"addr":"<destination_address>"}
  ```

- SENDTO

  ```json
  {"ts":<timestamp>,"event":"SENDTO","pid":<pid>,"len":<data_length>}
  ```

- RECVFROM

  ```json
  {"ts":<timestamp>,"event":"RECVFROM","pid":<pid>,"size":<buffer_size>}
  ```

- DUP2

  ```json
  {"ts":<timestamp>,"event":"DUP2","pid":<pid>,"oldfd":<old_fd>,"newfd":<new_fd>}
  ```

- WAIT4_EXITED：捕获 wait4返回，记录回收的子进程。

  ```json
  {"ts":<timestamp>,"event":"WAIT4_EXITED","pid":<pid>,"reaped_child":<child_pid>}
  ```

### 3.4 资源统计（每秒输出）

😍**Pay attention! This part will refresh each seconds. 但是也要在这一秒内有内存的申请或归还才会输出，及都为0的情况不会每秒刷新。如果你需要更改刷新的频率或者逻辑，可以联系我**

- FREE_SUM 统计调用次数

  ```json
  {"ts":<timestamp>,"pid":-1,"evt":"FREE_SUM","meta":{"count":<free_count>}}
  ```

- MMAP_SUM：统计调用次数及最大页面数。

  ```json
  {"ts":<timestamp>,"pid":-1,"evt":"MMAP_SUM","meta":{"count":<mmap_count>,"max_pages":<max_pages>}}
  ```

- ALLOC_SUM：统计 malloc  calloc、realloc调用次数。

  ```json
  {"ts":<timestamp>,"pid":-1,"evt":"ALLOC_SUM","meta":{"count":<alloc_count>}}
  ```

如果对逻辑不确定，详见附录

### 3.5 调度与信号

- SCHED_SWITCH：捕获上下文切换。

  ```json
  {"ts":<timestamp>,"event":"SCHED_SWITCH","prev_pid":<prev_pid>,"next_pid":<next_pid>}
  ```

- SIGNAL_GENERATE：捕获trap信号生成。

  ```json
  {"ts":<timestamp>,"event":"SIGNAL_GENERATE","pid":<pid>,"sig":<signal_number>}
  ```

------

### 3.6 SETUID

> 捕获 `setuid(uid)` 系统调用，监控进程尝试改变用户身份的行为。

```json
{
  "ts": <timestamp>,   // 单调时钟秒.微秒，脚本宏 TS 提供
  "event": "SETUID",   // 事件标识
  "pid": <pid>,        // 触发调用的进程 ID
  "uid": <uid>         // 目标用户 ID
}
```

- **ts**: `nsecs/1e9`
- **event**: `"SETUID"`
- **pid**: 进程号
- **uid**: 调用参数中传入的新 UID

------

### 3.7 MPROTECT

> 捕获 `mprotect(addr, len, prot)` 系统调用，将权限掩码拆为三个布尔字段。

```json
{
  "ts": <timestamp>,
  "event": "MPROTECT",
  "pid": <pid>,
  "read": <0|1>,   // 是否包含 PROT_READ
  "write": <0|1>,  // 是否包含 PROT_WRITE
  "exec": <0|1>    // 是否包含 PROT_EXEC
}
```

- **ts**: 单调时钟秒.微秒
- **event**: `"MPROTECT"`
- **pid**: 进程号
- **read**: `1` 表示原型中含有 `PROT_READ`，否则 `0`
- **write**: `1` 表示含有 `PROT_WRITE`，否则 `0`
- **exec**: `1` 表示含有 `PROT_EXEC`，否则 `0`

------

### 3.8 MADVISE

> 捕获 `madvise(addr, len, advice)` 系统调用，将 `advice` 值直接输出为字符串。

```json
{
  "ts": <timestamp>,
  "event": "MADVICE",
  "pid": <pid>,
  "advice": "<MADV_XXX>"
}
```

- **ts**: 单调时钟秒.微秒
- **event**: `"MADVICE"`
- **pid**: 进程号
- **advice**: 建议类型，脚本中映射为如
  - `"MADV_NORMAL"`
  - `"MADV_RANDOM"`
  - `"MADV_SEQUENTIAL"`
  - `"MADV_WILLNEED"`
  - `"MADV_DONTNEED"`
  - `"MADV_FREE"`
  - …若非以上则 `"MADV_OTHER"`

## 4. 使用方法

1. **运行脚本**：以 root 权限运行 bpftrace 脚本。
2. **输出解析**：事件输出到标准输出，可用工具（如 `jq`）解析。
3. **停止监控**：按 `Ctrl+C` 结束，输出 `END` 事件。

## 5. 注意事项

- 仅监控以 "qemu-" 开头的进程及其子进程。
- 资源统计每秒输出一次，汇总前一秒数据。
- 部分事件（如 `READ`、`WRITE`）缓冲区内容可能被截断。
- 使用 `uprobe` 监控 libc 内存分配，需确保 `/lib/x86_64-linux-gnu/libc.so.6` 路径正确。



#### 附录

```bash
interval:s:1
{
    /* FREE_SUM */
    if (@free_cnt) {
        printf("{\"ts\":%llu,\"pid\":-1,\"evt\":\"FREE_SUM\",\"meta\":{\"count\":%llu}}\n",
               nsecs/1000000000ULL, @free_cnt);
    }
    clear(@free_cnt);

    /* MMAP_SUM */
    if (@mmap_total) {
        printf("{\"ts\":%llu,\"pid\":-1,\"evt\":\"MMAP_SUM\",\"meta\":{\"count\":%llu,\"max_pages\":%llu}}\n",
               nsecs/1000000000ULL, @mmap_total, @mmap_max);
    }
    clear(@mmap_total);
    clear(@mmap_max);

    /* ALLOC_SUM */
    if (@alloc_cnt) {
       printf("{\"ts\":%llu,\"pid\":-1,\"evt\":\"ALLOC_SUM\",\"meta\":{\"count\":%llu}}\n",
       nsecs/1000000000ULL, @alloc_cnt);
    }
    clear(@alloc_cnt);
}
```

