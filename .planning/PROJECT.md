# Mercury（墨丘利）

## What This Is

Mercury 是面向网络管理员、校园网/企业内网运维人员和高级用户的分布式网络诊断工具。每台设备可运行 Mercury CLI；WebUI 发行物内置同一套 CLI 与诊断引擎，用统一、可解释的视图呈现本机网络、邻居与网关、互联网可达性、内网网段发现、路由路径，以及两个经授权 Mercury 节点之间的端口与协议可达性差异。

Mercury 的重点不是“某个 IP 能不能 ping 通”这一位结果，而是帮助用户回答“哪一层、哪一跳、哪个方向、哪个协议或端口出了问题”，并保存足够证据让问题可以复现和比较。

## Core Value

在用户明确授权的网络范围内，以安全、可解释且可复现的方式定位节点间可达性故障及其网络层原因。

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] CLI 可展示操作系统、主机、DNS、路由、网卡、地址、MTU、默认网关等本机网络快照。
- [ ] 在能力允许时识别直连邻居、网关及交换基础设施，并明确区分“观测到”“推断出”和“无法得知”。
- [ ] 通过多目标、多协议探针区分本地链路、DNS、默认路由、公共 IP 和常用外网服务的可达性。
- [ ] 在用户限定的授权范围内发现本机可见网段、活跃主机和基础服务，支持超时、并发、速率及目标上限。
- [ ] 分析到目标的路由路径、逐跳时延和路径变化，并对平台权限或 ICMP 过滤导致的不确定性作出解释。
- [ ] 两个 Mercury 端可通过显式配对进行双向协作测试，覆盖常用 TCP/UDP 端口和可扩展的应用层探针。
- [ ] 提供经强提醒和显式确认才可启用的高级矩阵测试，用采样/分片/预算机制避免无意执行 65,535 端口乘全部协议的爆炸式扫描。
- [ ] WebUI 内置 CLI/诊断引擎，提供实时任务进度、网络状态摘要、拓扑/路径视图、结果详情和历史对比。
- [ ] 任务、探针、观测、置信度、错误和事件使用版本化结构化模型，可输出 JSON 并生成可分享的脱敏报告。
- [ ] 默认只绑定 loopback、具有认证和最小权限控制；所有主动探测均保留授权范围与审计记录。
- [ ] 支持 Windows、Linux 和 macOS 的普通用户模式，并对需要原始套接字、抓包或系统命令权限的能力进行降级说明。
- [ ] 具备单元、集成、端到端和受控网络命名空间/容器测试，能验证成功、丢包、拒绝、超时、DNS 劫持及不对称路径等场景。

### Out of Scope

- 未经授权的互联网或第三方网络扫描 — Mercury 是诊断工具，不是公共攻击面扫描器。
- 默认穷举全端口、全协议、任意载荷组合 — 状态空间没有有限意义，风险和时间成本远超诊断价值。
- 声称在无 LLDP/CDP/SNMP/管理面信息时可靠识别二层交换机 — 普通终端通常无法仅从 IP 层确定交换设备。
- 绕过网络访问控制、封锁或认证 — 只观测与报告可达性，不提供规避机制。
- 通用漏洞利用、口令爆破、流量窃听或内容解密 — 与可达性诊断无关且会显著扩大双重用途风险。
- 在 v1 建设集中式多租户 SaaS 控制平面 — 首版聚焦本地 CLI/WebUI 与显式配对的点到点诊断。

## Context

- 用户希望解决校园网断网、DNS/特定端口仍放行、同一网络不同设备结果不一致等“表面断网、实际部分可达”的隐蔽问题。
- 参考项目为 [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail)；需先验证其架构、交互和代码模式是否适合复用，而不是机械复制。
- 同类问题已有 ping、traceroute、mtr、nmap、arp/neighbor、LLDP 客户端、NetBird/Tailscale diagnostics、OpenSpeedTest 等碎片化工具；Mercury 的候选价值在于跨平台整合、双端协作、方向性测试和可解释结果。
- 项目是 greenfield；技术栈、协议和打包方式将在研究阶段根据跨平台权限、UDP 语义、WebUI 供应链和单文件分发约束确定。
- “尽可能多地扫出来”解释为在显式授权范围和资源预算内采用多来源被动发现加渐进式主动探测，而不是无边界扫描。

## Constraints

- **安全**: 默认被动/低影响；主动扫描需要显式目标范围，危险模式需要二次确认、硬预算和审计。
- **真实性**: 不把推断包装成事实；每条结论附来源、时间、方向和置信度。
- **可移植性**: Windows、Linux、macOS 均须有可用的非特权基线，特权能力必须可选降级。
- **网络语义**: TCP connect 成功、拒绝、超时，UDP 响应/ICMP 不可达/静默必须分开表达；“静默”不等于“开放”。
- **隐私**: 存储和导出默认脱敏公网 IP、MAC、主机名及探测载荷中的敏感内容。
- **资源**: 扫描有并发、速率、目标数、端口数、持续时间和输出大小上限，可取消且不得阻塞 UI。
- **交付**: WebUI 与 CLI 共享同一诊断内核和数据模型；禁止维护两套行为不一致的实现。
- **许可**: 复用 Ponytail 或其他项目代码前必须核对许可证和归属要求。

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| 先验证产品价值再开发 | 现有工具很多，Mercury 必须在整合、解释和双端协作上形成清晰差异 | — Pending |
| 采用安全分层的探测模式 | 网络扫描具有双重用途，默认行为必须可控 | — Pending |
| WebUI 和 CLI 共用核心 | 避免行为漂移与重复维护 | — Pending |
| 使用证据与置信度模型 | 二层设备、UDP 和受过滤路由无法总是确定判断 | — Pending |
| “极端测试”采用有限预算矩阵 | “所有包种”不可枚举，诊断应围绕假设而非笛卡尔积暴力搜索 | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition**:
1. Requirements invalidated? Move to Out of Scope with reason.
2. Requirements validated? Move to Validated with phase reference.
3. New requirements emerged? Add to Active.
4. Decisions to log? Add to Key Decisions.
5. “What This Is” still accurate? Update if drifted.

**After each milestone**:
1. Full review of all sections.
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state.

---
*Last updated: 2026-07-30 after initialization*
