<!-- generated-by: gsd-doc-writer -->
# 配置指南

Mercury 不使用应用级 `.env` 文件。配置来源包括 CLI 参数、仅用于默认历史路径的两个标准环境变量、WebUI 证书/令牌文件，以及严格校验的 peer JSON。

## 环境变量

| 变量 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `LOCALAPPDATA` | 否 | Windows 上的 `~/AppData/Local` | `Mercury/history.sqlite3` 的根目录。 |
| `XDG_DATA_HOME` | 否 | 非 Windows 上的 `~/.local/share` | `mercury/history.sqlite3` 的根目录。 |

peer 令牌、证书、目标、扫描 profile 和 WebUI 凭据均不能通过环境变量提供。

## 历史配置

- Windows：`%LOCALAPPDATA%\Mercury\history.sqlite3`
- Ubuntu：`${XDG_DATA_HOME:-~/.local/share}/mercury/history.sqlite3`

用位于子命令之前的全局选项覆盖：

```bash
mercury --data-path <HISTORY.sqlite3> status
mercury --data-path <HISTORY.sqlite3> history list
```

历史和报告拒绝凭据、令牌及私钥材料。导出默认遮盖标识符和负载；`history export --retain-sensitive` 可保留这些标识符和负载，但始终不会保留凭据。

## WebUI 配置

| 选项 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--bind` | 否 | `127.0.0.1` | 已准入的数字私有地址。 |
| `--port` | 否 | `8765` | 监听端口；`0` 选择空闲端口。 |
| `--cert` | 非回环必需 | 无 | TLS 证书路径，须与 `--key` 同时提供。 |
| `--key` | 非回环必需 | 无 | TLS 私钥路径。 |
| `--token-file` | 非回环必需 | 无 | 包含非空令牌且可读的文件，令牌最长 512 字符。 |

```bash
mercury web --bind 127.0.0.1 --port 8765
mercury web --bind <本机私有IP> --port 8765 --cert <WEB证书.pem> --key <WEB私钥.pem> --token-file <WEB令牌.txt>
```

WebUI 使用服务器 TLS 加令牌；peer agent 则在非回环模式中使用 mTLS、令牌和证书指纹校验，两者不可混淆。

## peer JSON 格式

路径可为绝对路径，也可相对于 JSON 文件。JSON 中只保存路径，不保存秘密值。以下仅为模板：

```json
{
  "identity": "<PAIR-ID>",
  "bind_host": "<本机数据IP>",
  "control_bind_host": "<本机控制IP>",
  "control_port": 9443,
  "peer_addresses": ["<对端数据IP>"],
  "control_peer_addresses": ["<对端控制IP>"],
  "peer_pins": ["sha256:<64位小写十六进制>"],
  "certificate_path": "<本端PEER证书.pem>",
  "key_path": "<本端PEER私钥.pem>",
  "ca_path": "<受信客户端CA.pem>",
  "token_path": "<PAIR令牌.txt>",
  "server_hostname": "<对端证书名称>",
  "paired": {"tcp_port": 45001, "udp_port": 45002, "timeout_s": 3.0},
  "receivers": [
    {"profile": "tcp_tagged", "bind_host": "<本机数据IP>", "port": 45101, "timeout_s": 3.0},
    {"profile": "udp_tagged", "bind_host": "<本机数据IP>", "port": 45102, "timeout_s": 3.0},
    {"profile": "dns_udp", "bind_host": "<本机数据IP>", "port": 45103, "timeout_s": 3.0},
    {"profile": "dns_tcp", "bind_host": "<本机数据IP>", "port": 45104, "timeout_s": 3.0},
    {
      "profile": "tls_handshake",
      "bind_host": "<本机数据IP>",
      "port": 45105,
      "timeout_s": 3.0,
      "tls": {
        "certificate_path": "<RECEIVER证书.pem>",
        "key_path": "<RECEIVER私钥.pem>",
        "ca_path": "<RECEIVER信任CA.pem>",
        "server_name": "<RECEIVER证书名称>"
      }
    },
    {"profile": "http_exchange", "bind_host": "<本机数据IP>", "port": 45106, "timeout_s": 3.0},
    {"profile": "ssh_banner", "bind_host": "<本机数据IP>", "port": 45107, "timeout_s": 3.0}
  ],
  "coverage_profiles": [
    "tcp_connect", "tcp_tagged", "udp_tagged", "dns_udp", "dns_tcp",
    "icmp_echo", "tls_handshake", "http_exchange", "ssh_banner", "arp", "ipv6_nd"
  ]
}
```

### 必需字段与校验

| 字段 | 规则 |
| --- | --- |
| `identity` | 1–64 个字符；首字符为字母/数字，其余可含字母、数字、`.`、`_`、`-`；须与 CLI 一致。 |
| `bind_host` | 本机数字私有数据地址。 |
| `control_port` | `0..65535`；跨主机部署应使用固定非零端口。 |
| `peer_addresses` | 固定数字数据 peer 地址；paired 要求恰好一个，coverage 使用第一个已配置固定 peer。 |
| `peer_pins` | 非回环至少一个 `sha256:` 加 64 位小写十六进制指纹。 |

非回环 `bind_host` 必须同时配置 `certificate_path`、`key_path`、`ca_path`、`token_path`。服务器要求客户端证书受 `ca_path` 信任；两端还会校验指纹与令牌。若设置 `server_hostname`，它参与 TLS 名称验证。

从管理员已核验的 PEM 证书生成 Mercury 指纹：

```bash
python -c "import hashlib,ssl,sys; print('sha256:'+hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1], encoding='ascii').read())).hexdigest())" <对端证书.pem>
```

共享非空令牌应通过两端受保护的本地文件部署，不得写入 JSON、命令历史、源码、报告或截图。

### receiver 与 profile 规则

- receiver 仅支持 `tcp_tagged`、`udp_tagged`、`dns_udp`、`dns_tcp`、`tls_handshake`、`http_exchange`、`ssh_banner`。
- 端口为 `1..65535`，同一绑定地址/端口不得重复；超时为 `0.1..30` 秒。
- `tls_handshake` 必须含四个 `tls` 字段；非 TLS receiver 不得含 `tls`。
- `tcp_connect` 需要已配置的 `tcp_tagged` receiver。
- `icmp_echo`、`arp`、`ipv6_nd` 无 receiver 条目。只有平台提供所需观察能力时 ICMP 才有 peer 到达证据，否则报告能力缺口。
- `coverage_profiles` 必须与 `mercury coverage --profiles` 完全一致。
- ARP/IPv6 ND 只适用于同链路；用 `--local-network` 与 `--peer-network` 明确判断适用性。

## 控制地址与数据地址（含 Tailscale）

默认控制与数据使用同一组地址。可选拆分如下：

| 用途 | 本机字段 | 对端字段 |
| --- | --- | --- |
| 控制通道 | `control_bind_host` | `control_peer_addresses` |
| 被测数据路径 | `bind_host` 与 receiver `bind_host` | `peer_addresses` |

Mercury 接受 RFC 6598 的 `100.64.0.0/10`，因此管理员可将 Tailscale 地址用于经过认证的控制通道，同时让物理/VLAN 实验地址留在数据字段中。

Mercury 不发现 Tailscale peer、不配置 ACL、不签发证书，也不会自动信任 overlay。mTLS、令牌、指纹、固定地址和授权仍然必需。若把 Tailscale 地址放入数据字段，评估测试的是 overlay 路径，而不是底层隔离边界。

## mapping 默认值与上限

默认 rate 为 `10`、concurrency 为 `1`、duration 为 `0`。普通编译上限为：256 主机、64 端口、4,096 次尝试、10,000 个数据报/逻辑包/事件、8 MiB 应用数据与输出、全局速率 100、单目标速率 10、并发 64、时长 300 秒。代码中的绝对上限更高但不可取消；duration 0 从不关闭上限。

用 `mercury model --json` 查看当前模型语义和绝对上限；用 `mercury plan ...` 在主动执行前查看成本与确认要求。

## 启动与验证

```bash
mercury agent --config <本端-PEER.json>
mercury paired --config <本端-PEER.json> --identity <PAIR-ID> --address <已配置对端数据IP> --timeout 3 --authorized
mercury coverage --config <本端-PEER.json> --identity <PAIR-ID> --address <已配置对端数据IP> --profiles <完全一致的配置列表> --timeout 3 --authorized
```

`--unsafe-development` 仅允许回环开发，非回环 `bind_host` 会直接拒绝，部署中不得使用。

## 分环境配置

Mercury 没有开发/预发/生产配置合并器。应为每个环境维护独立、受管理员保护的 peer JSON 与信任文件，并用 `--config` 显式选择；历史库可用全局 `--data-path` 分离。
