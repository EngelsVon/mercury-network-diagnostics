<!-- generated-by: gsd-doc-writer -->
# Mercury

[English](README.md)

Mercury 是一款本地优先的网络诊断工具，面向需要在明确授权的私有网络内获取可复现可达性证据的管理员。

Mercury 的 CLI、对端代理和 WebUI 共用同一套 Python 引擎与版本化证据模型。它保留各协议结果之间的差异，不把静默误判为成功或失败，并明确报告每项结论的适用边界。

> Mercury 仅用于私有网络。主动任务只接纳所选操作支持的环回地址、RFC1918 IPv4、RFC6598 共享 IPv4、IPv6 ULA 以及带作用域的 IPv6 链路本地地址。公网、文档专用、多播、未指定和广播目标会在网络或原生工具 I/O 前被拒绝。非环回任务必须显式声明已获授权。多范围 `mapping` 的范围更窄：只接受环回与 RFC1918 IPv4 CIDR。

## 功能矩阵

| 能力 | Mercury 提供的功能 | 重要边界 |
| --- | --- | --- |
| 被动状态与发现 | 接口、路由、DNS、邻居、Wi-Fi、能力，以及平台能够提供时的直接 LLDP 证据 | 不会把网关、路由跃点或 ARP/ND 邻居标为交换机 |
| 分层诊断 | 针对选定私有端点的有界 DNS、TCP、TLS、HTTP、原生 ping 与路由证据 | 结果仅适用于选定端点和已观测层次 |
| 内网测绘 | 针对多个私有 IPv4 CIDR、固定配置文件、选定端口、速率、并发和时长生成一份不可变计划 | 主动任务受主机、端口、尝试、逻辑报文、应用字节、速率、并发、时长、事件和输出上限约束 |
| 双端覆盖评估 | 带方向的 TCP、UDP、DNS over UDP/TCP、ICMP、TLS、HTTP、SSH banner，以及同链路 ARP/IPv6 ND 证据 | 可接收配置文件需要由管理员预置、互为对端的 Mercury 节点 |
| 可选 Nmap 证据 | 固定的 TCP connect、TCP SYN、UDP 和 SCTP INIT 配置文件，并解析有界 XML | 不接受任意参数、脚本、目标文件、代理、诱饵、载荷或目标 |
| WebUI | 无障碍任务创建、进度、取消、覆盖矩阵、缺口与本地历史 | 浏览器代码不执行网络探测；非环回监听必须使用 TLS 和令牌 |
| 历史与报告 | 本地 SQLite 任务历史、比较、JSON 与 HTML 报告 | 凭据始终被拒绝或脱敏；标识符和载荷默认脱敏 |

Mercury v1 的发布目标为 Windows 和 Ubuntu。不支持的原生能力会作为证据报告，而不会被静默忽略。macOS 和其他平台不是发布目标。

## 安装

Mercury 需要 CPython 3.11 或更高版本，唯一运行时依赖为 `psutil`。在源码检出目录中可用 `uv` 或 `pip` 安装：

```bash
uv tool install .
mercury --help
```

```bash
python -m venv .venv
# PowerShell：.venv\Scripts\Activate.ps1
# Ubuntu：source .venv/bin/activate
python -m pip install .
python -m mercury --help
```

从源码目录开发时，先执行 `uv sync`，再执行 `uv run python -m mercury --help`，即可使用锁定环境。完整步骤见[入门指南](docs/zh-CN/GETTING-STARTED.md)。

## 快速开始

最安全的首次运行是被动操作，不发送探测：

1. 查看 CLI 与证据契约。

   ```bash
   mercury --help
   mercury model
   ```

2. 收集本地状态证据。

   ```bash
   mercury status
   mercury status --json
   ```

3. 收集被动发现证据。

   ```bash
   mercury discover --passive
   ```

执行主动任务前，可用 `mercury plan --help` 预览并计算授权任务的成本。绝不要替换为公网、第三方或未经批准的目标。

## 内网测绘

`mapping` 会把重叠的私有 IPv4 CIDR、选定的固定配置文件与端口规范化为一份不可变的出站计划。`--rate` 的单位是每秒逻辑尝试启动数。`--duration 0` 只取消操作员指定的提前截止时间；编译后的硬性上限仍会终止任务。

```bash
mercury mapping \
  --cidr <自有私有CIDR> \
  --profiles tcp_connect,udp_tagged \
  --ports 53,80,443 \
  --rate 20 \
  --concurrency 4 \
  --duration 0 \
  --authorized
```

尖括号中的值是占位符。只能将其替换为由你管理且获准测试的私有 IPv4 CIDR。

## 内网测绘与双端覆盖评估

### 覆盖接收端配置

双端评估使用管理员创建、互为对端的配置文件。每份文件固定对端身份和地址、控制通道、证书与令牌路径、证书指纹、允许的覆盖配置文件以及接收端口。CLI 无法把对端变成任意第三方扫描中继。

对端 JSON 会绑定有限的 `coverage_profiles` 列表和接收端表；完整字段与互为对端的示例见[配置](docs/zh-CN/CONFIGURATION.md)。

可接收配置文件包括 `tcp_tagged`、`udp_tagged`、`dns_udp`、`dns_tcp`、`tls_handshake`、`http_exchange` 和 `ssh_banner`。`tcp_connect` 使用已配置的 TCP 接收端。`icmp_echo` 使用平台原生证据；无法观察对端到达时会记录观察能力缺口。`arp` 和 `ipv6_nd` 是同链路证据，对于跨子网端点对会标为 `not_applicable`。

在每个已配置端点启动其本地代理：

```bash
mercury agent --config <本机对端配置.json>
```

然后在一个端点发起评估，参数必须与其配置完全匹配：

```bash
mercury coverage \
  --config <本机对端配置.json> \
  --identity <已配置身份> \
  --address <已配置私有对端地址> \
  --profiles tcp_tagged,udp_tagged,dns_udp,dns_tcp,icmp_echo,tls_handshake,http_exchange,ssh_banner,arp,ipv6_nd \
  --local-network <自有本机私有CIDR> \
  --peer-network <自有对端私有CIDR> \
  --authorized
```

评估会在两个方向分别运行适用配置文件，并关联发送端证据与对端回执。DNS 配置文件不会执行通用域名解析，SSH 配置文件也不会尝试凭据或登录。

## 可选 Nmap

如果本机安装了 `nmap` 可执行文件，每个测绘任务可以且只能选择以下一个封闭原生配置文件：

- `nmap_tcp_connect`
- `nmap_tcp_syn`
- `nmap_udp`
- `nmap_sctp_init`

Mercury 会先验证私有计划，再自行派生完整的 Nmap 参数向量。结果以原生来源保留 `open`、`closed`、`filtered` 和 `open|filtered` 状态。可执行文件缺失、权限不足、超时、输出异常或配置文件不支持，都会保留为不同的能力或错误证据。Mercury 不提供任意 Nmap 命令行接口。

## WebUI

启动本地仪表板：

```bash
uv run --no-sync python -m mercury web
```

打开命令输出的环回 URL。WebUI 与 CLI 一样向 `MercuryApplication` 提交同一类强类型请求，支持被动状态、诊断、发现、路由跟踪、测绘、双端覆盖、进度、取消、历史比较和脱敏报告。

如需有意监听非环回地址，必须提供私有数字绑定地址、证书/密钥对和令牌文件：

```bash
mercury web \
  --bind <私有监听地址> \
  --cert <证书.pem> \
  --key <私钥.pem> \
  --token-file <令牌文件>
```

以上均为占位符，并非随项目附带的凭据。监听器还会校验 Host 头、同源变更请求、会话 Cookie 与 CSRF 头，以及有界 JSON 请求体。Web 模式不暴露对端代理控制面。

## 证据语义

每条观测记录都包含证据种类、语义处置、方向、目标、起止时间、耗时、尝试编号、来源以及有界详情。结论通过观测 ID 引用支持证据，并附带置信度、替代解释与局限性。

- 肯定证据表示选定交换获得了定义明确的响应或关联的对端到达记录；它并不能证明更广泛的拓扑或已部署隧道。
- TCP 拒绝或 ICMP 不可达等直接否定证据，会与超时和静默分开保存。
- 超时和静默属于不确定结果，绝不会被呈现为端口关闭、隔离成功或网络失败。
- 不支持、权限不足、跳过和不适用行是覆盖缺口或适用性说明，不是否定可达性证据。
- 有限双端矩阵可以识别已测试的候选承载通道，但不能证明所有未经测试的载荷、状态序列、协议或隧道均不存在。

规范解释见[证据语义](docs/zh-CN/EVIDENCE-SEMANTICS.md)，共用执行路径见[架构](docs/zh-CN/ARCHITECTURE.md)。

## 历史与报告

```bash
mercury history list
mercury history show <任务ID>
mercury history compare <较早任务ID> <较新任务ID>
mercury history export <任务ID> --format html
```

只有任务种类和模型架构兼容的已完成记录才能比较。某次运行缺少证据，只表示该次运行没有记录到它，并不能证明某种网络状态。`--retain-sensitive` 可以在本地导出中保留标识符和载荷，但绝不会保留凭据、令牌或私钥。

## 文档

| English | 简体中文 |
| --- | --- |
| [Getting Started](docs/GETTING-STARTED.md) | [入门指南](docs/zh-CN/GETTING-STARTED.md) |
| [Architecture](docs/ARCHITECTURE.md) | [架构](docs/zh-CN/ARCHITECTURE.md) |
| [Evidence Semantics](docs/EVIDENCE-SEMANTICS.md) | [证据语义](docs/zh-CN/EVIDENCE-SEMANTICS.md) |
| [CLI Reference](docs/CLI-REFERENCE.md) | [CLI 参考](docs/zh-CN/CLI-REFERENCE.md) |
| [Configuration](docs/CONFIGURATION.md) | [配置](docs/zh-CN/CONFIGURATION.md) |
| [Deployment](docs/DEPLOYMENT.md) | [部署](docs/zh-CN/DEPLOYMENT.md) |
| [Development](docs/DEVELOPMENT.md) | [开发](docs/zh-CN/DEVELOPMENT.md) |
| [Testing](docs/TESTING.md) | [测试](docs/zh-CN/TESTING.md) |
| [Contributing](CONTRIBUTING.md) | [贡献指南](CONTRIBUTING.zh-CN.md) |
| [Security](SECURITY.md) | [安全](SECURITY.zh-CN.md) |
| [Code of Conduct](CODE_OF_CONDUCT.md) | [行为准则](CODE_OF_CONDUCT.zh-CN.md) |
| [Mercury network-diagnostics skill](skills/mercury-network-diagnostics/SKILL.md) | 同一技能文档 |

## 开发与验证

### 操作员发布冒烟检查

受控测试套件只使用伪实现、固定样例和环回地址，不会联系真实的非环回目标。

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m build
```

## 许可证

见 [LICENSE](LICENSE)。
