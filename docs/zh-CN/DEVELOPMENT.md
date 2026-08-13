<!-- generated-by: gsd-doc-writer -->
# 开发指南

[English](../DEVELOPMENT.md)

Mercury 是采用 `src/` 布局的 CPython 3.11+ 项目。v1 的发布目标是 Windows 和 Ubuntu，当前开发与测试使用可用的 Python 3.13。运行时依赖只有 `psutil`；CLI、代理和 Web UI 共用同一个 Python 服务层，Web UI 使用语义化 HTML、CSS 和原生 JavaScript，不需要前端构建系统。

## 本地环境

安装 [uv](https://docs.astral.sh/uv/) 和 Python 3.11 或更高版本，然后从派生仓库或检出目录开始：

```powershell
git clone <你的派生仓库地址>
cd Mercury-dev
uv sync
uv run --no-sync python -m mercury --help
```

常规开发和测试不需要环境变量文件或配置生成步骤。Nmap 是可选能力；测试默认使用替身。只有操作者明确选择固定原生配置并在获授权的私有网络中运行时，才应调用本机 Nmap。

## 常用命令

`pyproject.toml` 定义了 `mercury` 控制台入口，但没有项目任务别名。请直接运行下列仓库命令：

| 命令 | 说明 |
| --- | --- |
| `uv run --no-sync python -m mercury --help` | 验证源码检出和 CLI 入口。 |
| `uv run --no-sync python -m unittest discover -s tests -v` | 运行完整的受控测试套件。 |
| `uv run --no-sync python -m compileall -q src tests` | 编译全部源码与测试模块。 |
| `uv run --no-sync ruff check src tests` | 执行文档规定的 Ruff 检查；Ruff 是开发工具，不是锁定的项目依赖。 |
| `uv build` | 构建源码包和 wheel。 |
| `uv run --no-sync python -m mercury status --json` | 在不进行主动探测的情况下检查被动状态路径。 |

## 代码风格

- 遵循现有的类型化、标准库优先的 Python 风格，并保持 Python 3.11+ 兼容。
- 运行 `uv run --no-sync ruff check src tests`。仓库目前没有单独的 Ruff 配置文件，因此采用其标准规则。
- 保留证据语义：连接被拒、超时、UDP 响应、ICMP 不可达、静默、不支持、权限不足和执行错误不能混为一谈。
- 不得削弱网络与信任边界验证、不可变工作上限、取消、敏感信息过滤或无障碍性。只有标准库和现有依赖无法以更小方案解决时，才增加框架或抽象。
- 展示层必须调用 `MercuryApplication`，不得自行打开探测套接字或启动原生扫描子进程。

## 分支与提交约定

当前检出的默认开发分支是 `master`。仓库未规定分支命名格式；可使用 `fix/timeout-evidence`、`docs/testing-guide` 等简短且含义明确的名称。

近期历史采用简短、祈使语气的 Conventional Commits 风格主题，包括 `feat:`、`fix:`、`docs:` 以及可选作用域。请沿用此模式，并保持提交小而可独立验证。

## 拉取请求流程

- 向 `master` 提交范围单一的拉取请求，并说明对操作者可见的行为和安全影响。
- 有相关 issue 时请关联；切勿在公开 issue 或拉取请求中写入尚未披露的漏洞细节。
- 每项行为变更都应新增或更新受控测试。测试只能使用替身、固定夹具或回环地址，绝不能扫描公网或未经授权的非回环目标。
- 运行完整测试、编译、Ruff 和构建命令，并如实报告平台相关的跳过或失败。
- 用户可见行为变化时，应同步文档、CLI 帮助、Web 文案和共享证据模型。
- 完成仓库拉取请求模板中的验证、安全、兼容性、敏感信息处理和中英文文档检查项。
- 评审会重点检查私有范围准入、授权、硬预算、证据语义、敏感信息处理、对等端/Web 信任控制，以及 Windows/Ubuntu 兼容性。

GitHub CI 会在 Windows 和 Ubuntu 上使用 Python 3.11 与 3.13 运行完整测试及编译检查，在 Ubuntu/Python 3.13 上构建发行包，并在两个平台上执行已安装 wheel 的被动状态冒烟测试。
