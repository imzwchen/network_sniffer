# Linux 网络嗅探器

当前版本通过 libpcap 实时抓包、保存和读取离线 `.pcap`。ncurses 界面提供协议树、BPF 和显示过滤、双向 TCP 追踪、实时 PID 归属、流量统计及应用层分析。

## 在 Ubuntu 24.04 / WSL2 中运行

需要 `uv`、带 `curses` 的 Python 3.12 和系统 libpcap 运行库。离线查看可以用普通用户运行。

```bash
sudo apt install libpcap0.8t64
uv sync
uv run network-sniffer --read sample.pcap
```

### 实时抓包

先列出可用网卡，再选择接口启动采集。实时抓包需要打开 Linux 抓包套接字的权限。下面以 Ubuntu / WSL2 的 `lo` 为例，用 `sudo` 启动项目虚拟环境中的程序。

```bash
uv run network-sniffer --list-interfaces
sudo -- "$PWD/.venv/bin/network-sniffer" --interface lo --snaplen 128 --write loopback.pcap
```

在另一个终端执行 `ping -c 3 127.0.0.1` 产生流量。`--snaplen` 设置每包最多捕获的字节数，默认是 65535。`--write` 可省略，指定时文件必须是新文件。按 `s` 停止抓包会把已采集的数据刷入文件，再按 `s` 继续写入同一个文件。

如果用 `sudo` 抓包，输出文件由 root 持有。退出抓包后，可将文件交给当前用户并离线回放。

```bash
sudo chown -- "$(id -u):$(id -g)" loopback.pcap
uv run network-sniffer --read loopback.pcap
```

实时界面最多保留最近 512 个可浏览的数据包。`pcap drops` 来自 libpcap，`queue drops` 记录应用队列已满时未送达界面的包。启用 `--write` 后，采集线程会先写入 `.pcap`，再尝试将包放入界面队列。

### 协议过滤

`--capture-filter` 使用 libpcap 的 BPF 语法，在采集阶段筛选要保留和写入 `.pcap` 的包。离线回放也可以用这个选项筛选从文件读入的包，原文件保持原样。BPF 中的 IPv4、IPv6 和 ICMPv6 分别写作 `ip`、`ip6` 和 `icmp6`。 [libpcap BPF 语法](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-filter.manmisc.in)

```bash
sudo -- "$PWD/.venv/bin/network-sniffer" --interface lo --capture-filter 'tcp or icmp6' --write filtered.pcap
uv run network-sniffer --read sample.pcap --capture-filter 'udp or icmp'
```

显示过滤在 TUI 中按 `/` 编辑。`Enter` 应用，`Esc` 取消，`Ctrl+U` 清空输入后按 `Enter` 恢复显示所有已读入或仍保留的包。界面会显示匹配数量。无效表达式会显示错误列号并保留上一条规则。

- 协议名支持 `tcp`、`udp`、`ipv4`、`ipv6`、`icmp`、`icmpv6`、`arp` 和 `vlan` 等。
- 支持括号和 `not`、`and`、`or`，优先级从高到低依次为 `not`、`and`、`or`。
- 数值字段支持 `==`、`!=`、`<`、`<=`、`>`、`>=`。例如 `(ipv4 or ipv6) and tcp and dst.port == 80`，也可用 `tcp.flags == 0x02` 或 `frame.len >= 128`。
- 地址字段如 `src.ip`、`dst.ip`、`ipv4.src`、`ipv6.dst` 支持 `==` 和 `!=`。例如 `ipv6 and src.ip == ::1`。
- 字段缺失时，比较结果为未知，取反后也保持未知。例如 ICMP 包缺少端口，`not dst.port == 80` 不会因此匹配它。

### 追踪 TCP 流

在包列表或详情视图选中任意 TCP 包，按 `Enter` 打开对应的流。可以先用显示过滤定位端点，例如 `(src.ip == 127.0.0.1 and src.port == 8080) or (dst.ip == 127.0.0.1 and dst.port == 8080)`。流详情按连接编号显示两个方向的包、握手与关闭状态，以及每个方向的包数、帧字节数和捕获的 TCP 载荷字节数。实时追踪在包进入界面队列之前完成，离线追踪在首次打开流详情时索引已经读入的包。

在流详情里，`1` 显示包列表，`2` 和 `3` 分别查看 A→B 和 B→A 重组的载荷，`Esc` 返回。重组按 TCP 序列号排列捕获的字节，遇到重叠使用最先捕获的字节，并显示重复的字节数。`[gap N bytes]` 标记已知序列范围内的缺失字节，`Start not observed` 表示未看到发起连接的 SYN。IP 分片只使用首片中可读的 TCP 信息。

实时追踪最多保留 1024 条流、4096 个 TCP 包和 16 MiB 的载荷来源数据，任一上限达到时会清理较旧的历史。仍保留的流会显示省略的包数。需要查看完整采集记录时，可以保存 `.pcap` 后离线打开。

### 按 PID 追踪 TCP 流

实时抓包时传入 `--pid`，界面会直接打开进程流列表。程序通过 `/proc/<pid>/fd` 和 `NETLINK_SOCK_DIAG` 周期查询 IPv4 和 IPv6 socket，并按端点和观测时间关联已捕获的流。可重复传入 `--pid`，同一 socket 的多个已选持有者会一起显示。PID 归属属于当前实时会话。 [Linux 进程文件描述符](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) · [Linux socket diagnostics](https://man7.org/linux/man-pages/man7/sock_diag.7.html)

`Enter` 打开所选流，`u` 显示或隐藏归属未知的流，`Esc` 返回包浏览器，`p` 回到进程流列表。列表还会显示进程退出、PID 复用、权限不足或网络命名空间不一致。`--capture-filter` 继续决定采集哪些包，`--pid` 决定进程视图关注哪些流。

安装 `bpftrace` 且运行环境允许加载内核探针时，程序会自动接收 TCP `connect` 和 `accept` 事件，补充可能在两次快照之间打开并关闭的连接。界面显示 `Kernel events active` 后可以测试短连接。事件不可用时会显示原因并继续轮询，无法确认的流显示为 `Unknown`。 [bpftrace 探针文档](https://bpftrace.org/docs/0.21#probes)

实测时先在一个终端启动本机回显服务。下面的参数 `2` 会让服务端在收到数据后持有连接两秒。

```bash
uv run python -u - 2 <<'PY'
import os
import socket
import sys
import time

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 18765))
    listener.listen()
    print("PID", os.getpid())
    while True:
        with listener.accept()[0] as peer:
            data = peer.recv(1024)
            time.sleep(float(sys.argv[1]))
            peer.sendall(data)
PY
```

在另一个终端把 `12345` 替换成服务打印的 PID，并开始抓包。

```bash
sudo -- "$PWD/.venv/bin/network-sniffer" --interface lo --pid 12345 --capture-filter 'tcp port 18765'
```

在第三个终端发起连接。抓包界面应显示该 PID 的流，在流详情可看到归属来源。验证短连接时先用 `sudo apt install bpftrace` 准备事件依赖，将服务参数 `2` 改为 `0`，再用新 PID 启动抓包并等到 `Kernel events active`。

```bash
uv run python -c 'import socket; s=socket.create_connection(("127.0.0.1", 18765)); s.sendall(b"pid trace"); print(s.recv(1024)); s.close()'
```

```bash
uv run --locked python -m unittest discover -s tests -p 'test_process_tracker.py' -v
```

### 界面操作

标题栏显示当前文件、采集状态或正在查看的流，标签页和底部快捷键栏用于切换视图。包列表在宽终端上分成列表和选中包预览，在窄终端上切回单栏。选中项、警告和错误既有颜色，也有文字或符号提示。设置 `NO_COLOR=1` 可使用无色界面。

| 按键 | 操作 |
| --- | --- |
| `1` / `2` / `3` | 打开包列表 / 协议树 / 十六进制视图 |
| `Tab` | 循环切换视图 |
| `←` / `→` | 上一个 / 下一个包 |
| `↑` / `↓` | 在列表选包，或滚动协议树和十六进制内容 |
| `Page Up` / `Page Down` | 在当前视图翻页 |
| `/` | 编辑显示过滤表达式 |
| `Enter` | 打开当前 TCP 包的流详情 |
| `Esc` | 退出流详情或取消编辑过滤规则 |
| `p` | 打开已配置 PID 的进程流列表 |
| `u` | 在进程流列表中显示或隐藏归属未知的流 |
| `v` | 打开或返回流量统计 |
| `s` | 开始或停止实时采集 |
| `f` | 回到最新数据包并跟随实时流量 |
| `q` | 退出 |

打开文件或开始实时采集时，默认显示十六进制视图。协议树每行的 `偏移+长度` 从帧头起算，偏移用十六进制表示，长度以字节计并用十进制表示。比如 `0022+2` 指从 `0x22` 开始的两个字节。截断、分片、格式错误和未支持的协议会在协议树顶部标明，仍可查看已经解析出的字段。

### 协议解析

- 链路层支持 Ethernet、VLAN（包括堆叠标签）和 Linux cooked capture（SLL、SLL2）。
- 网络层支持 ARP、IPv4、IPv6，以及 IPv6 的 Hop-by-Hop、Routing、Destination Options、Fragment 和 Authentication 扩展头。
- 传输层与控制报文支持 TCP、UDP、ICMP 和 ICMPv6。IP 首片中可读的传输层字段会照常显示，后续分片可查看分片偏移和原始字节。

`sample.pcap` 含有三条合成的 Ethernet 帧，分别为 TCP SYN、UDP 和截断的 ICMP Echo Request。第二帧有足够的内容用于测试滚动，第三帧的捕获长度小于原始长度。

离线查看器会在进入界面前读取整个文件，适合查看小型离线样本。

### 流量统计与应用层分析

在包浏览器或 PID 流列表中按 `v` 打开统计视图，按 `1`、`2`、`3` 分别查看协议、IP 端点和会话，按 `Esc` 返回。每个包会记入它已解析的各层协议。总计显示包数、原始帧字节和实际捕获字节。IP 端点表区分发送和接收，会话表按 TCP 流和双向 UDP 端点对汇总。统计在显示过滤和界面队列之前采集，实时视图显示 libpcap 丢包数和界面队列丢包数。端点表最多保留 4096 个地址，UDP 会话表最多保留 2048 对端点，淘汰数量会显示在表头。

UDP DNS 可在协议树中查看事务 ID、查询名、常见回答记录等字段，也可以用 `dns and dns.response == 1` 筛选。选中 TCP 包后按 `Enter`，再按 `4` 打开流分析。该视图显示各方向的疑似重传、无歧义 ACK 对应的 RTT 样本，以及重组后可见的 DNS over TCP、HTTP/1.x 和 TLS Hello 信息。TLS 视图可显示可见的服务器名称、版本和 ALPN。每方向最多分析前 128 KiB 的连续载荷，遇到缺口时会标出停止位置。 [DNS](https://www.rfc-editor.org/rfc/rfc1035.html) · [HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html) · [TLS 握手](https://www.rfc-editor.org/rfc/rfc8446.html#section-4) · [TCP RTT 采样](https://www.rfc-editor.org/rfc/rfc6298.html#section-3)

### 验证命令

专项测试核对 DNS、HTTP、TLS、统计、重传和 RTT。完整回归测试覆盖前面的阶段。

```bash
uv run --locked python -m unittest discover -s tests -p 'test_analysis.py' -v
uv run --locked python -m unittest discover -s tests -v
```

用自带的样本打开统计视图。按 `v` 后应看到 `3 packets`、`566 frame B` 和 `532 captured B`。

```bash
uv run network-sniffer --read sample.pcap
```

验证实时 HTTP 分析时，先在一个终端启动抓包。

```bash
sudo -- "$PWD/.venv/bin/network-sniffer" --interface lo --capture-filter 'tcp port 18765'
```

等界面显示 `Capturing`，在另一个终端产生一次本机 HTTP 请求和响应。回到抓包界面选中任意一个 TCP 包，按 `Enter` 再按 `4`，应看到 `HTTP GET /demo` 和 `HTTP 200 OK`。

```bash
uv run python - <<'PY'
import socket

request = b"GET /demo HTTP/1.1\r\nHost: localhost\r\n\r\n"
response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 18765))
    listener.listen()
    with socket.create_connection(listener.getsockname()) as client:
        with listener.accept()[0] as server:
            client.sendall(request)
            assert server.recv(len(request), socket.MSG_WAITALL) == request
            server.sendall(response)
            assert client.recv(len(response), socket.MSG_WAITALL) == response
PY
```
