# Requirements: Mercury（墨丘利）

**Defined:** 2026-07-30  
**Core Value:** 在用户明确授权的网络范围内，以安全、可解释且可复现的方式定位节点间可达性故障及其网络层原因。

## v1 Requirements

### Evidence and task semantics

- [x] **EVID-01**: 用户获得的每次诊断结果都包含模式版本、任务 ID、方向、目标、开始/结束时间、有效配置和结构化观测。
- [x] **EVID-02**: 用户能区分成功、拒绝、超时、静默、不支持、权限不足和执行错误，而不会把 UDP/ICMP 静默误报为确定结论。
- [x] **EVID-03**: 用户看到的结论包含置信度、支持它的观测和可能的其他解释。
- [x] **EVID-04**: 用户可以取消长任务，并保留状态为 cancelled 的有效部分结果。

### Safety and authorization

- [x] **SAFE-01**: 用户发起主动探测前能看到规范化目标范围和预计主机、端口、尝试次数及最坏耗时。
- [x] **SAFE-02**: 系统对每个任务强制执行主机数、端口数、逻辑尝试、Mercury 生成的 UDP 数据报/应用载荷字节、全局与每目标 attempt-start 速率、并发数、持续时间、事件数和输出大小的不可绕过绝对上限；绝对上限至少允许单主机 1–65535 TCP 检查，但不允许多维无界笛卡尔积，且不得声称精确计量内核重传或线上帧开销。
- [x] **SAFE-03**: 任何非 loopback 主动任务都需要用户显式声明已获目标授权；全 TCP 端口模式和自定义 UDP 载荷还分别需要独立危险确认。
- [x] **SAFE-04**: 用户输入的 IPv4、IPv6、CIDR 和主机名在连接时按解析后的每个地址重新接受范围策略检查。
- [x] **SAFE-05**: 非 loopback 的 Mercury agent 在没有 TLS 证书、私钥、受信客户端证书和访问令牌时拒绝启动；仅显式开发覆盖可关闭 mTLS，且必须产生醒目审计警告。

### Local network inventory

- [ ] **INVT-01**: 用户能查看主机名、操作系统、Mercury/Python 版本、采集时间和本机能力/降级原因。
- [ ] **INVT-02**: 用户能查看各网卡的名称、状态、IPv4/IPv6 地址与前缀、MAC、MTU和可用时的链路速度。
- [ ] **INVT-03**: 用户能查看默认网关、路由和 DNS 服务器；某个平台无法结构化读取时会看到明确的 unavailable/error 证据。
- [x] **INVT-04**: 用户能查看被动 ARP/NDP 邻居，以及在 `lldpctl -f json` 可用时看到 LLDP 邻居。
- [x] **INVT-05**: 用户界面明确区分网关、L2 邻居、首个路由跳、Wi-Fi AP 与 LLDP 基础设施；没有直接证据时显示“无法从本机观测交换机”。

### Layered diagnosis

- [ ] **DIAG-01**: 用户可以运行 basic 诊断，分别检查本地接口/路由、DNS、公共 IP 的 TCP、TLS 和多个常用 HTTPS 目标。
- [ ] **DIAG-02**: 用户可以选择面向中国常用站点的 profile，或通过 CLI 指定额外的 host:port 目标与超时。
- [ ] **DIAG-03**: 每个 DNS/TCP/TLS/HTTP/native-ping 探针均报告分层结果、耗时、尝试次数和错误证据。
- [ ] **DIAG-04**: CLI 同一诊断可输出简洁人类可读摘要或稳定 JSON，并用退出码区分 healthy、partial 和 failed。

### Discovery and route analysis

- [x] **DISC-01**: 用户无需发送探测包即可先看到从接口、路由和邻居缓存推导出的可见网段与候选主机。
- [x] **DISC-02**: 用户可在显式授权 CIDR 中以有界并发扫描版本化常用 TCP 端口 profile，并逐步看到进度。
- [x] **DISC-03**: 用户可显式选择任意 TCP 端口范围（包括 1–65535），但任务仍受预算、时间上限和危险确认约束。
- [x] **DISC-04**: IPv6 discovery 只使用显式地址和被动邻居，不枚举巨大 IPv6 网段。
- [x] **DISC-05**: 用户可追踪到目标的路由，选择可用的 native 模式、重复次数和超时，并保留未响应跳及原始命令证据。

### Paired Mercury diagnostics

- [x] **PEER-01**: 运维者可以启动带协议版本、能力和审计信息的 Mercury agent；远程控制默认使用 mTLS 与已配置证书指纹识别两端，并以可轮换 bearer token 作为独立授权因子；token/私钥不得进入 URL、结果、历史或日志。
- [x] **PEER-02**: 运维者可显式配置 agent 为单个有界计划临时监听的 TCP/UDP 测试端口，并查看每个端口成功、占用、过期或权限不足状态。
- [x] **PEER-03**: 用户输入另一 Mercury agent 的 IP/主机名后，可以验证身份/能力并协商一个角色互换的固定分层计划，比较两端本机快照、DNS、到对端的路径、TCP/UDP 以及允许列表内的 TLS/HTTP 证据。
- [x] **PEER-04**: 用户能看到 A→B 与 B→A 的发送、到达、回复和接收关联证据及分层差异矩阵，从而区分端点、方向、协议/端口、解析和路径差异；每个解释都链接原始观察。
- [x] **PEER-05**: 用户可请求 agent 只向当前已认证控制连接的源 IP 执行有界反向 TCP 检查；agent 不接受任意第三方扫描目标。
- [x] **PEER-06**: 高级 UDP 测试只允许内置有限载荷 profile 或不超过 1400 字节的显式载荷，受包/字节/速率预算与独立危险确认约束，并清楚声明“所有包种”不可穷举。

### WebUI, history, and reports

- [ ] **WEB-01**: 用户运行 `mercury web` 后可在默认 loopback WebUI 查看分层健康、网卡、网关/DNS、邻居/LLDP 和能力信息。
- [ ] **WEB-02**: 用户可从 WebUI 提交 basic 诊断、paired 差异诊断、授权 discovery 和 route 任务，轮询查看进度、取消并打开结构化结果及 A↔B 分层矩阵。
- [ ] **WEB-03**: WebUI 使用与 CLI 完全相同的服务函数和结果模型，不维护第二套探测逻辑。
- [ ] **WEB-04**: WebUI 默认仅绑定 loopback，并校验 Host、Origin、SameSite session、CSRF header、请求体上限和 CSP；非 loopback 绑定在没有 TLS 证书、私钥和访问令牌时拒绝启动，除非用户显式启用仅供开发的不安全模式。
- [x] **HIST-01**: 用户的任务请求、有效计划、状态和原始结果保存在仅当前用户可访问的本地 SQLite 中，并受数量/时间保留上限控制；token、私钥、配对密钥和未截断自定义载荷永不持久化。
- [ ] **HIST-02**: 用户可从 CLI/WebUI 查看和比较两个兼容的历史任务，并导出 JSON 或自包含 HTML 报告。
- [ ] **HIST-03**: 导出默认脱敏访问令牌、主机名、MAC、公网 IP 和原始载荷；用户必须显式选择保留敏感字段。

### Packaging, compatibility, and verification

- [ ] **PACK-01**: 用户从同一个 Python wheel/安装目录获得 `mercury` CLI、agent 和 WebUI 静态资源。
- [ ] **PACK-02**: Windows 和 Ubuntu 普通用户都能运行 inventory、TCP/TLS/HTTP 和 WebUI 基线，并看到特权/工具缺失的降级说明；macOS 及其他平台明确报告为 unsupported，不属于 v1 发布目标。
- [x] **TEST-01**: 维护者能用标准库测试运行证据模型、目标策略、预算、状态迁移、历史保留及取消逻辑。
- [ ] **TEST-02**: 维护者能在受控环境验证成功、拒绝、超时/丢弃、UDP 静默、DNS 失败、延迟和不对称路径，而 CI 不会扫描未授权公网。
- [ ] **TEST-03**: 维护者能用标准库测试平台解析器、Web API 安全边界、peer mTLS/token 鉴权、重放/越权拒绝和双端证据关联。
- [ ] **DOCS-01**: 用户文档包含安全授权说明、快速开始、各平台能力、TLS agent 配置、结果语义和明确非目标。

## v2 Requirements

### Existing-tool integrations

- **INTG-01**: 用户可导入或调用 Nmap XML 结果作为深度扫描证据。
- **INTG-02**: 用户可调用 iperf3 JSON 作为可选吞吐 profile。
- **INTG-03**: 用户可比较多次 route/diagnose 基线并高亮变化。

### Deployment ergonomics

- **DIST-01**: 用户可下载经过签名的 Windows/Ubuntu 独立可执行发行物。
- **PAIR-01**: 用户可通过经过安全评审的人类可验证短码完成证书/身份配对。
- **HELP-01**: 可选的最小特权 helper 提供经评审的原始 ICMP/LLDP 能力。

### Operations

- **METR-01**: 用户可选择导出 Prometheus/OpenTelemetry 指标。
- **FLEET-01**: 管理员可在自托管控制面管理多个 Mercury 节点和计划任务。

## Out of Scope

| Feature | Reason |
|---------|--------|
| 未经授权的互联网或第三方扫描 | Mercury 是诊断工具；法律和运营风险不可接受 |
| 穷举“所有包种” | 载荷空间无限，无法完成也没有诊断意义 |
| 漏洞利用、口令爆破、规避封锁 | 与可达性解释无关并显著提高双重用途风险 |
| 自研 Nmap/iperf3/LLDP/pcap 替代品 | 现有成熟工具已覆盖，违反 Ponytail/YAGNI |
| 无证据识别透明二层交换机 | 普通终端在 IP 层无法可靠做到 |
| v1 React/Vue、Web 框架、ORM、消息队列、插件 SDK | 本地小规模需求可由标准库直接满足 |
| 默认远程明文 agent/WebUI | 会形成内部扫描和信息泄露入口 |
| v1 集中式多租户 SaaS | 不属于本地/点到点核心价值 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| EVID-01 | Phase 1 | Complete |
| EVID-02 | Phase 1 | Complete |
| EVID-03 | Phase 1 | Complete |
| EVID-04 | Phase 1 | Complete |
| SAFE-01 | Phase 1 | Complete |
| SAFE-02 | Phase 1 | Complete |
| SAFE-03 | Phase 1 | Complete |
| SAFE-04 | Phase 1 | Complete |
| SAFE-05 | Phase 3 | Complete |
| INVT-01 | Phase 2 | Complete |
| INVT-02 | Phase 2 | Complete |
| INVT-03 | Phase 2 | Complete |
| INVT-04 | Phase 4 | Complete |
| INVT-05 | Phase 4 | Complete |
| DIAG-01 | Phase 2 | Complete |
| DIAG-02 | Phase 2 | Complete |
| DIAG-03 | Phase 2 | Complete |
| DIAG-04 | Phase 2 | Complete |
| DISC-01 | Phase 4 | Complete |
| DISC-02 | Phase 4 | Complete |
| DISC-03 | Phase 4 | Complete |
| DISC-04 | Phase 4 | Complete |
| DISC-05 | Phase 4 | Complete |
| PEER-01 | Phase 3 | Complete |
| PEER-02 | Phase 3 | Complete |
| PEER-03 | Phase 3 | Complete |
| PEER-04 | Phase 3 | Complete |
| PEER-05 | Phase 3 | Complete |
| PEER-06 | Phase 3 | Complete |
| WEB-01 | Phase 5 | Pending |
| WEB-02 | Phase 5 | Pending |
| WEB-03 | Phase 5 | Pending |
| WEB-04 | Phase 5 | Pending |
| HIST-01 | Phase 1 | Complete |
| HIST-02 | Phase 5 | Pending |
| HIST-03 | Phase 5 | Pending |
| PACK-01 | Phase 5 | Pending |
| PACK-02 | Phase 5 | Pending |
| TEST-01 | Phase 1 | Complete |
| TEST-02 | Phase 5 | Pending |
| TEST-03 | Phase 5 | Pending |
| DOCS-01 | Phase 5 | Pending |

**Coverage:**

- v1 requirements: 42 total
- Mapped to phases: 42
- Unmapped: 0

---
*Requirements defined: 2026-07-30*  
*Last updated: 2026-07-30 after roadmap creation*
