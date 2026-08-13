<!-- generated-by: gsd-doc-writer -->
# 入门指南

Mercury 是一款本地优先的网络诊断工具，用可复现证据测试已明确授权的私有网络。v1 的发布目标为 Windows 和 Ubuntu。

## 前置条件

- CPython 3.11 或更高版本；开发与 CI 使用 Python 3.13。
- 唯一运行时依赖为 `psutil>=7.0,<8`，安装 Mercury 时会自动安装。
- 推荐使用 `uv`；标准虚拟环境与 `pip` 同样可用。
- 可选：若要使用四种固定原生配置，需要在同一环境的 `PATH` 中安装 `nmap`。SYN、UDP、SCTP 扫描可能需要操作系统权限；工具缺失或权限不足会作为能力证据报告。
- 双端覆盖评估还需要两端均安装 Mercury、管理员预置的互反 peer JSON、令牌文件以及双向 TLS（mTLS）证书。

主动目标仅可为回环、RFC1918 IPv4、RFC 6598 共享地址空间（`100.64.0.0/10`）、IPv6 ULA 或带作用域的 IPv6 链路本地地址。非回环任务仍必须显式授权。

## 安装 Mercury

### 从源码检出安装

仓库当前未配置公开远程 URL。请将 `<仓库地址>` 替换为已获授权的来源。

Windows PowerShell：

```powershell
git clone <仓库地址> mercury
cd mercury
uv sync
uv run python -m mercury --help
```

Ubuntu：

```bash
git clone <仓库地址> mercury
cd mercury
uv sync
uv run python -m mercury --help
```

使用 `pip`：

```bash
python -m venv .venv
# Ubuntu: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
mercury --help
```

也可在仓库根目录安装为本地 CLI 工具：

```bash
uv tool install .
mercury --help
```

## 首次运行

先执行不发起主动扫描的被动状态采集：

```bash
mercury status
mercury status --json
```

结果会区分可用、不可用、权限不足和执行错误。没有直接 LLDP 或受管证据时，网关、路由跳点或邻居不会被标注为交换机。

安全的回环主动检查：

```bash
mercury diagnose --profile basic --authorized
```

对自有私有实验网络，应先预览有界工作，再执行：

```bash
mercury plan <私有IP或CIDR> --ports 80,443 --scope <已授权私有CIDR> --authorized
mercury mapping --cidr <已授权私有IPv4-CIDR> --profiles tcp_connect --ports 80,443 --rate 10 --concurrency 1 --duration 30 --authorized
```

`--duration 0` 只表示不增加操作员选择的提前截止时间，编译后的不可变硬上限仍然有效。

## 启动 WebUI

默认启动仅回环可访问的 HTTP 监听器：

```bash
mercury web
```

打开 `http://127.0.0.1:8765`。`--port 0` 可选择空闲端口。浏览器只调用与 CLI 相同的应用服务，不直接进行网络探测。

非回环监听必须提供私有数字绑定地址、TLS 证书/私钥和非空令牌文件：

```bash
mercury web --bind <本机私有IP> --port 8765 --cert <WEB证书.pem> --key <WEB私钥.pem> --token-file <WEB令牌.txt>
```

不要把令牌值写入命令行或 peer JSON。

## 可选 Nmap 配置

通过操作系统认可的软件源安装 Nmap，并确认同一运行环境中的 `nmap --version` 可用。Mercury 只查找本机 `PATH` 中的可执行文件，并从已准入计划生成固定参数。

每个 mapping 任务只能选择一种原生配置：

```bash
mercury mapping --cidr <已授权私有IPv4-CIDR> --profiles nmap_tcp_connect --ports 22,80,443 --rate 10 --concurrency 1 --duration 30 --authorized
```

支持 `nmap_tcp_connect`、`nmap_tcp_syn`、`nmap_udp`、`nmap_sctp_init`。Mercury 不提供任意 Nmap 参数、脚本、目标文件、代理、诱饵或负载选项。原生 `open`、`closed`、`filtered`、`open|filtered` 状态会保留 Nmap 来源。

## 双端覆盖评估

1. 按[配置指南](CONFIGURATION.md)建立互反 peer 配置。管理员提供地址、端口、证书路径、指纹和令牌文件前，请只使用占位符。
2. 在两端启动 agent：

   ```bash
   mercury agent --config <本端-PEER.json>
   ```

3. 从一端运行与配置文件完全相同的 profile 集：

   ```bash
   mercury coverage --config <本端-PEER.json> --identity <PAIR-ID> --address <已配置对端数据IP> --profiles tcp_connect,tcp_tagged,udp_tagged,dns_udp,dns_tcp,icmp_echo,tls_handshake,http_exchange,ssh_banner,arp,ipv6_nd --local-network <本地私有CIDR> --peer-network <对端私有CIDR> --timeout 3 --authorized
   ```

peer 命令不能指定第三方目标。可接收的 profile 使用固定本地 receiver。ARP 与 IPv6 ND 仅表示同链路证据，跨子网时为 `not_applicable`。候选载体只证明记录中的有限 profile 在该方向和时间窗内有效；静默和未覆盖的报文形状不能证明所有可能隧道都不存在。

## 常见问题

### `nmap executable unavailable`

确认同一终端中 `nmap --version` 可用且目录已加入 `PATH`，否则改用非原生 profile。不要尝试向请求添加任意可执行文件或参数字段。

### 原生或 ICMP 任务权限不足

部分 Nmap 模式和 ICMP 观察需要额外系统权限。请选用权限更低的受支持 profile，或按管理制度提升权限。该结果是能力缺口，不是连通性结论。

### 非回环 WebUI 被拒绝

同时提供 `--cert`、`--key`、`--token-file`，绑定已准入的数字私有地址，并确认文件可读。回环监听无需这三项。

### peer 配置被拒绝

确认两端身份相同、固定地址互反、`--address` 等于配置的数据 peer 地址，并确保每个 receiver 使用唯一固定端口。非回环 peer 必须具备证书、私钥、受信客户端 CA、令牌文件，以及 `sha256:` 加 64 位小写十六进制的证书指纹。

### 历史数据库位置不符预期

全局选项必须放在子命令之前：`mercury --data-path <路径> status`。Windows 默认为 `%LOCALAPPDATA%\Mercury\history.sqlite3`，Ubuntu 默认为 `${XDG_DATA_HOME:-~/.local/share}/mercury/history.sqlite3`。

## 后续阅读

- [配置指南](CONFIGURATION.md)
- [部署指南](DEPLOYMENT.md)
- [CLI 参考](CLI-REFERENCE.md)
