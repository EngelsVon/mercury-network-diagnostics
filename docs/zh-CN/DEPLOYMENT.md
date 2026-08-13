<!-- generated-by: gsd-doc-writer -->
# 部署指南

Mercury 以本地 Python CLI/WebUI 方式部署；双端评估时，由管理员在两台 Windows 或 Ubuntu 端点运行进程。仓库没有 Docker、Compose、Vercel、Netlify、Fly.io、Railway、Serverless 或生产自动部署配置。

## 部署目标

| 目标 | 支持角色 | 安装方式 |
| --- | --- | --- |
| CPython 3.11+ 的 Windows | CLI、WebUI、peer agent | wheel/虚拟环境或 `uv tool install .` |
| CPython 3.11+ 的 Ubuntu | CLI、WebUI、peer agent | wheel/虚拟环境或 `uv tool install .` |
| 其他平台 | 非 v1 发布目标 | 已实现能力会明确报告不支持。 |

Mercury 本地优先，不是集中式远程扫描服务；peer agent 只暴露封闭的已配置操作。

## 构建流水线

在受控源码检出中构建 wheel：

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m build
```

在目标环境安装：

```bash
python -m venv .venv
# Ubuntu: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install psutil
python -m pip install --no-index --no-deps <MERCURY-WHEEL.whl>
python -m mercury --help
python -m mercury status --json
```

仓库 CI `.github/workflows/phase2-passive-status.yml` 在 push、pull request 和手动触发时运行：在 Windows/Ubuntu + Python 3.13 上构建安装 wheel，并采集经净化的被动状态证据。它不发布或部署 Mercury；仓库没有 CI/CD 部署流水线。

## Windows 部署

1. 安装 CPython 3.11+，创建专用虚拟环境或 `uv` 工具环境。
2. 安装已审核 wheel 和 `psutil`。
3. 用计划中的服务账号执行 `python -m mercury status --json`。
4. 若需原生 profile，通过管理员认可的 Windows 软件源安装 Nmap，并确认该账号能执行 `nmap --version`。
5. 将历史库、令牌、私钥、peer JSON 和证书存放在管理员控制的目录，用 ACL 限制为 Mercury 账号和管理员可读。
6. 如需后台运行，使用环境认可的 Windows 服务包装器。仓库不提供 Windows 服务定义。

## Ubuntu 部署

1. 安装 CPython 3.11+，创建专用虚拟环境或 `uv` 工具环境。
2. 安装已审核 wheel 和 `psutil`。
3. 用计划中的服务账号执行 `python -m mercury status --json`。
4. 若需原生 profile，安装发行版 Nmap 包并确认 `nmap --version`。只授予所选 profile 所需权限，不要默认以 root 运行全部 Mercury 操作。
5. 令牌、私钥、证书、配置和历史路径应仅对 Mercury 账号可读。需要自定义历史位置时设置 `XDG_DATA_HOME` 或使用 `--data-path`。
6. 如需自启动，使用管理员审核的服务单元。仓库不提供 `systemd` unit。

## 生产环境准备

完整 schema 与默认值见[配置指南](CONFIGURATION.md)。每组双端部署应：

1. 分配一个固定 peer 控制端口和互不冲突的固定 receiver 端口。
2. 明确哪些地址是控制面、哪些地址是被测数据路径。
3. 用管理员控制的 CA 签发端点证书，确保名称和用途正确。
4. 互反配置客户端 CA、本机证书/私钥、精确的对端证书指纹以及共享令牌文件。
5. 创建互反 JSON：双方 identity 与 profile 集一致，数据/控制 peer 地址指向对方。
6. 只在计划时间窗内开放选定控制与 receiver 端口。
7. 两端运行 `mercury agent --config <本端-PEER.json>`。
8. 从一端执行有界且已授权的评估，按本地制度保留证据和历史。

不得在回环之外部署 `--unsafe-development`。非回环 peer 必须使用 mTLS、令牌和证书指纹；非回环 WebUI 另需 TLS 与令牌。

## WebUI 部署

推荐仅回环：

```bash
mercury web --bind 127.0.0.1 --port 8765
```

有意开放到私有非回环地址时：

```bash
mercury web --bind <本机私有IP> --port 8765 --cert <WEB证书.pem> --key <WEB私钥.pem> --token-file <WEB令牌.txt>
```

内置服务器校验 Host/Origin 状态，使用 SameSite 会话 Cookie 与 CSRF 请求头，限制请求体并发送内容安全策略。它仍是操作员界面：应限制网络访问、保护令牌文件，并使用浏览器信任的证书。Web 模式不暴露 peer-agent 控制。

## Tailscale 控制通道选项

若管理员已运行 Tailscale，可用 `control_bind_host` 与 `control_peer_addresses` 将 peer 控制绑定到已准入的 `100.64.0.0/10` 地址，同时让 `bind_host`、`peer_addresses` 和 receiver 地址保留为被测私有网络地址。

这种拆分避免把控制路径误当成数据路径证据。Mercury 不安装或管理 Tailscale；其 ACL、设备注册、DNS 和可用性属于外部部署责任。Mercury 的 mTLS、令牌和指纹要求仍然强制。若目标是测试其他底层路径，不要使用 Tailscale 数据地址。

## Nmap 部署

Nmap 为可选能力，必须位于 Mercury 同机同用户环境的 `PATH` 中。每个 mapping 任务仅支持 `nmap_tcp_connect`、`nmap_tcp_syn`、`nmap_udp` 或 `nmap_sctp_init` 中的一种。Mercury 内部生成 `-n -Pn --reason`、固定扫描选择器、有界速率/超时/端口、XML 输出和已准入数字目标。

权限要求取决于操作系统和 profile。可执行文件缺失、权限不足、非零退出、超时、XML 错误及原生端口状态会保持区分。能力失败或 `filtered`/`open|filtered` 不能被解释为 Mercury 直接 socket 观察。

## 发布烟雾测试

仅在自有和受管网络执行：

```bash
python -m mercury version --json
python -m mercury model --json
python -m mercury status --json
python -m mercury discover --passive --json
python -m mercury diagnose --profile basic --authorized --json
```

随后在回环验证 WebUI。若部署 peer，先启动两端已配置 agent，再以短超时运行小型已配置 profile 集。不得替换为公网、文档保留或无权使用的地址。

## 回滚

仓库没有自动回滚机制。

1. 停止 WebUI/agent 进程，并按需保留本地历史。
2. 在虚拟环境中重装上一个已审核 wheel，或将服务命令切回上一个不可变环境。
3. 从受保护备份恢复匹配的 peer JSON 与信任文件；证书、指纹和地址必须互相一致。
4. 重启非回环监听前，执行 `python -m mercury --help`、`status --json` 和回环烟雾测试。
5. 如果信任材料可能泄露，应轮换令牌和证书，而不是恢复旧秘密。

## 监控与运维

仓库没有 Sentry、Datadog、New Relic、OpenTelemetry 或外部监控集成。应监控操作系统进程，并按本地保留制度采集已净化的 CLI JSON/历史导出。SQLite 历史默认位于用户数据目录，可用全局 `--data-path` 移动。

应分别对进程退出和带类型的能力/终止状态告警。静默、超时和缺失观察不是成功健康检查。覆盖评估是有限的：正向关联到达只识别候选载体，负向结果仅覆盖记录的 profile、方向、端口、报文形状和时间窗。
