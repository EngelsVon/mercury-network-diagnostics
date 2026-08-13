<!-- generated-by: gsd-doc-writer -->
# CLI 参考

控制台入口为 `mercury`，与 `python -m mercury` 等价。主动命令仅可用于已明确授权的私有范围。

## 全局语法

```text
mercury [--version] [--json] [--data-path PATH] COMMAND ...
```

全局选项须位于子命令之前。大多数子命令也有自己的 `--json`。

| 选项 | 说明 |
| --- | --- |
| `--version` | 输出软件包版本并退出。 |
| `--json` | 输出稳定 JSON。 |
| `--data-path PATH` | 覆盖 SQLite 历史路径。 |

## 退出码

| 代码 | 含义 |
| --- | --- |
| `0` | 被动/任务成功，或结论健康。 |
| `1` | 明确失败的任务/诊断结论。 |
| `2` | 输入无效。 |
| `3` | 授权、范围、预算或确认策略拒绝。 |
| `4` | 部分、混合、已取消、静默、不可用或不确定。 |
| `70` | 内部或结果契约错误。 |

## 信息与被动命令

### `version`

```bash
mercury version [--json]
```

### `model`

```bash
mercury model [--json]
```

输出证据语义和不可变绝对上限；静默始终是不确定结果。

### `status`

```bash
mercury status [--json]
```

按平台能力采集本地主机、接口、路由、DNS、邻居、Wi-Fi、LLDP 与能力证据。

## 诊断、发现、测绘和路由

### `diagnose`

```text
mercury diagnose [--profile basic] [--target HOST:PORT ...] [--timeout SECONDS] [--authorized] [--json]
```

`--target` 可重复；一旦使用即切换为精确自定义端点集。超时默认 `3.0`，范围 `0.1..30`。非回环必须 `--authorized`，解析后的地址会再次接受私有范围检查。

```bash
mercury diagnose --profile basic --authorized
mercury diagnose --target <私有主机>:443 --target [::1]:443 --timeout 3 --authorized --json
```

### `discover`

```text
mercury discover --passive [--json]
mercury discover --network CIDR --scope CIDR [--profile common|custom|full] [--ports PORTS] [--timeout SECONDS] [--authorized] [--confirm PHRASE ...] [--json]
```

被动模式不能与主动选项组合。主动模式是有界 IPv4 TCP 发现。`custom` 要求 `--ports`；`full` 是有限的 `1..65535` TCP 端口 profile，需要预览产生的摘要绑定确认，并非无界或“所有协议”扫描。

```bash
mercury discover --passive
mercury discover --network <私有CIDR> --scope <已授权私有CIDR> --profile common --authorized
```

### `mapping`

```text
mercury mapping --cidr CIDR [--cidr CIDR ...] --profiles LIST --ports PORTS [--rate N] [--concurrency N] [--duration SECONDS] [--authorized] [--json]
```

默认 rate `10`（每秒逻辑尝试开始数）、concurrency `1`、duration `0`。CIDR 可重复，但仅接受私有 IPv4。直接 profile 为 `tcp_connect`、`tcp_tagged`、`udp_tagged`、`dns_udp`、`dns_tcp`、`tls_handshake`、`http_exchange`、`ssh_banner`；原生 profile 为 `nmap_tcp_connect`、`nmap_tcp_syn`、`nmap_udp`、`nmap_sctp_init`，每个任务只能选一种原生 profile。

```bash
mercury mapping --cidr <私有CIDR-A> --cidr <私有CIDR-B> --profiles tcp_connect,udp_tagged --ports 53,80,443 --rate 20 --concurrency 4 --duration 60 --authorized
```

duration 0 表示普通不可变上限内不增加操作员提前截止时间，不表示无限任务。

### `trace`

```text
mercury trace TARGET --scope CIDR [--hops N] [--repeat N] [--timeout SECONDS] [--authorized] [--json]
```

`TARGET` 是一个数字私有 IP。默认 8 跳、3 次重复、每跳等待 1 秒。无响应与不同跳点会保留为证据；路由跳点不会被标注为交换机。

```bash
mercury trace <私有IP> --scope <已授权私有CIDR> --authorized
```

## 计划预览

```text
mercury plan TARGET [TARGET ...] [--ports PORTS] [--transport tcp|udp ...]
  [--repeat N] [--payload-bytes N] [--payload-sha256 HEX]
  [--payload-profile NAME] [--datagrams N] [--authorized]
  [--scope CIDR ...] [--name HOSTNAME ...] [--purpose TEXT]
  [--custom-udp] [--absolute-limits] [--json]
```

默认端口 `80,443`、TCP、一次重复、无负载、一个 UDP 数据报，purpose 为 `interactive diagnosis`。该命令只规范化与计算成本，不执行 I/O。`--payload-sha256` 记录已批准自定义 UDP 负载的元数据，原始负载不持久化。`--absolute-limits` 只用于按硬上限预览，不能取消上限。

## 认证 peer

### `agent`

```text
mercury agent --config FILE [--unsafe-development] [--json]
```

启动封闭 peer 控制监听器和已配置短期 receiver。非回环需要 mTLS、令牌与证书指纹；`--unsafe-development` 仅限回环。

### `paired`

```text
mercury paired --config FILE --identity ID --address PEER-DATA-IP [--timeout SECONDS] [--authorized] [--unsafe-development] [--json]
```

运行固定 paired profile。identity/address 必须与配置相同；CLI 没有任意目标、端口或负载控制。超时默认 `3.0`，范围 `0.1..30`。

### `coverage`

```text
mercury coverage --config FILE --identity ID --address PEER-DATA-IP --profiles LIST
  [--timeout SECONDS] [--local-network CIDR] [--peer-network CIDR]
  [--authorized] [--unsafe-development] [--json]
```

profiles 必须与配置集完全一致。receiver-capable 矩阵包括 TCP tagged/connect、UDP tagged、DNS over UDP/TCP、TLS handshake、HTTP exchange、SSH banner。ICMP echo 使用本机能力，仅在支持时附带 peer 到达证据。ARP/IPv6 ND 是同链路被动证据；使用两个 network 参数明确适用性。

```bash
mercury coverage --config <本端-PEER.json> --identity <PAIR-ID> --address <已配置对端数据IP> --profiles <完全一致的配置列表> --local-network <本地私有CIDR> --peer-network <对端私有CIDR> --timeout 3 --authorized
```

结果保留双方向，以及候选载体、直接负向、不确定、不支持、权限不足、跳过、不适用等结论。它不会证明所有可能报文或隧道都不存在。

## WebUI

```text
mercury web [--bind NUMERIC-IP] [--port N] [--cert FILE] [--key FILE] [--token-file FILE]
```

默认 `127.0.0.1:8765`，端口 `0` 选择空闲端口。非回环需要证书、私钥和令牌文件：

```bash
mercury web --bind <本机私有IP> --port 8765 --cert <WEB证书.pem> --key <WEB私钥.pem> --token-file <WEB令牌.txt>
```

## 历史

```bash
mercury history list [--limit N] [--json]
mercury history show TASK_ID [--json]
mercury history compare LEFT_TASK_ID RIGHT_TASK_ID [--json]
mercury history export TASK_ID [--format json|html] [--retain-sensitive] [--json]
```

`list` 默认最多 50 条。只有类型与模型 schema 兼容的已完成任务可比较；证据缺失不等于失败观察。导出默认 JSON，并遮盖标识符与负载；`--retain-sensitive` 可保留二者，但凭据、令牌和私钥始终遮盖。

## 离线开发命令

`mercury task synthetic [--steps N] [--delay SECONDS] [--cancel-after SECONDS] [--json]` 在无网络 I/O 的情况下测试有界生命周期。它在顶层帮助中隐藏，不是操作员扫描命令。

## 安全解释

- 公网、文档保留、多播、未指定、广播及解析后逃逸范围的目标会在主动 I/O 前拒绝。
- `--authorized` 是明确授权声明，不会绕过目标或预算策略。
- TCP 拒绝/复位、超时、UDP 响应/静默、ICMP 不可达、不支持、权限不足和执行错误保持区分。
- Nmap 状态保留原生来源，不会改写成 Mercury 直接 socket 观察。
- 正向关联结果只识别一个已测试候选载体；静默或负向有限矩阵不能证明所有隧道或任意报文序列都不存在。
