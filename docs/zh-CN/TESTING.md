<!-- generated-by: gsd-doc-writer -->
# 测试指南

[English](../TESTING.md)

## 框架与准备

Mercury 使用 Python 标准库的 `unittest` 框架，包括用于异步行为的 `IsolatedAsyncioTestCase` 和用于受控边界的 `unittest.mock`。测试需要 Python 3.11+ 和项目运行时依赖 `psutil`。

在仓库根目录运行：

```powershell
uv sync
```

测试套件不需要公网服务或测试账号。`tests/fixtures/tls/` 下的 TLS 材料仅用于测试，绝不能用于生产监听器、客户端凭据或信任库。

## 运行测试

运行完整测试套件：

```powershell
uv run --no-sync python -m unittest discover -s tests -v
```

使用点分名称运行单个模块、类或方法：

```powershell
uv run --no-sync python -m unittest tests.test_policy -v
uv run --no-sync python -m unittest tests.test_policy.TargetPolicyTests -v
uv run --no-sync python -m unittest tests.test_policy.TargetPolicyTests.test_only_explicit_internal_address_spaces_are_admitted -v
```

运行项目文档规定的发布检查：

```powershell
uv run --no-sync python -m compileall -q src tests
uv run --no-sync ruff check src tests
uv build
```

仓库未配置测试监听模式命令。

## 编写测试

- 将测试放在 `tests/test_<领域>.py`，使用 `unittest.TestCase` 或 `unittest.IsolatedAsyncioTestCase`，方法名采用 `test_<行为>`。
- 使用 `tests/helpers.py` 创建代表性的版本化观察和结果。平台数据放在 `tests/fixtures/platform/`，仅限回环的 TLS 材料放在 `tests/fixtures/tls/`。
- 受控 I/O 应使用替身、模拟、临时目录和回环地址（`127.0.0.0/8` 或 `::1`）。绝不能解析或连接真实公网目标、用户提供的对等端或其他未经授权的非回环目标。
- 断言类型化结果及其来源。静默和超时仍是不确定；拒绝、重置、响应、ICMP 不可达、不支持、权限不足和错误状态必须保持区分。
- 新增主动路径时，应证明授权、私有范围策略、DNS 复核、不可变预算和取消会按需在 I/O 之前或期间生效。
- 明确跨平台预期。POSIX 权限位测试在 Windows 上会跳过，因为 Windows ACL 的语义不同。

常用的定向测试包括：`test_policy.py` 检查准入和预算，`test_tasks.py` 检查生命周期与持久化，`test_paired.py` 和 `test_peer.py` 检查关联证据与对等信任，`test_nmap_adapter.py` 检查固定原生命令边界，`test_web.py`/`test_cli.py` 检查共享服务路由。

## 覆盖率要求

仓库没有配置行、分支、函数或语句覆盖率阈值。行为需求通过定向回归测试覆盖，但目前没有公布数字化覆盖率目标或覆盖率命令。

## CI 集成

`.github/workflows/ci.yml` 定义了 `CI`，在 push、pull request 和手动触发时运行。

`tests` 作业会在 `windows-latest` 和 `ubuntu-latest` 上使用 Python 3.11 与 3.13，安装项目和 `build`，运行完整测试与编译检查，并在 Ubuntu/Python 3.13 上构建发行包。

`installed-passive-status` 作业会：

1. 使用 `python -m pip wheel . --no-deps` 构建 wheel。
2. 创建干净虚拟环境并安装 `psutil` 和该 wheel。
3. 运行 `python -m mercury status --json`。
4. 验证被动任务已完成，并包含明确的 `no_direct_lldp_or_managed_evidence` 接入交换机可观测性限制。
5. 上传已脱敏的状态产物。

CI 不运行 Ruff，因此贡献者仍应在提交拉取请求前于本地执行文档规定的 Ruff 检查。
