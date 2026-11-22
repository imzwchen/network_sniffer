# Linux 网络嗅探器

基于 libpcap 实时抓包和读取 PCAP，使用 ncurses 终端界面查看协议、TCP 流和流量统计。

## 项目架构

```
- capture.py: 封装 libpcap 接口，实现底层抓包、离线读写与 BPF 过滤
- dissect.py: 多协议解析与异常检测
- tcp_flow.py: TCP 状态机追踪、流重组及序列号计算
- live.py: 多线程实时抓包控制器、状态同步与缓冲区管理
- process_tracker.py & process_events.py: 网络流的进程 PID 归属判定
- traffic_stats.py: 流量统计与LRU缓存管理
- tui.py / tui_theme.py / flow_view.py / traffic_view.py: TUI 渲染与交互逻辑
```

## 部署

```bash
sudo apt update
sudo apt install libpcap0.8t64
uv sync --locked
```

## 运行

```bash
./run.sh
```

