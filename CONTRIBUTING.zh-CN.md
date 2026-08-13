<!-- generated-by: gsd-doc-writer -->
# 为 Mercury 做贡献

[English](CONTRIBUTING.md)

感谢你帮助改进 Mercury。贡献必须保留其核心承诺：只在明确授权的私有网络范围内提供安全、可复现的可达性证据，不把推断或静默当作事实。

## 开发环境

请阅读 [安装说明](README.md#installation) 了解前置条件与首次运行步骤，阅读[开发指南](docs/zh-CN/DEVELOPMENT.md)了解本地环境和项目命令，并阅读[测试指南](docs/zh-CN/TESTING.md)了解受控测试要求。

## 编码标准

- 支持 CPython 3.11+ 以及 Windows、Ubuntu 发布目标。
- 优先使用标准库和现有的 `psutil` 依赖。Mercury 有意不引入前端框架或额外运行时框架。
- 运行 `uv run --no-sync ruff check src tests`、`uv run --no-sync python -m compileall -q src tests` 和完整 `unittest` 套件。
- 明确保留并测试证据语义、授权、私有范围检查、不可变预算、敏感信息过滤、对等端/Web 信任控制及无障碍性。

## 拉取请求准则

- 从 `master` 创建分支。仓库不强制固定分支命名格式，请使用简短且含义明确的名称。
- 提交主题采用简短、祈使语气的 Conventional Commits 风格，例如 `feat: add ...`、`fix: preserve ...` 或 `docs: clarify ...`。
- 每个拉取请求保持范围单一，并说明行为、证据、安全和兼容性影响。
- 新增或更新测试。测试只能使用替身、固定夹具或回环地址，不得接触公网或未经授权的非回环目标。
- 完成拉取请求模板并运行[测试指南](docs/zh-CN/TESTING.md)中的检查。CI 会在 Windows/Ubuntu、Python 3.11/3.13 上运行完整测试和编译，构建发行包并执行已安装包的被动冒烟；Ruff 仍需本地运行。
- 共享行为变化时同步更新用户文档、CLI 帮助和 Web 文案，不得增加仅存在于展示层的探测路径。

## 报告问题

提交 issue 前，请先搜索[已有 issue](https://github.com/EngelsVon/mercury-network-diagnostics/issues)，并使用仓库的缺陷或功能模板。报告缺陷时请提供：

- 仅使用自有或明确授权私有网络的最小复现；
- 预期行为和实际类型化证据；
- Mercury 版本、Python 版本、操作系统、命令和已脱敏输出；
- 是否可稳定复现，以及可选原生工具是否可用。

请移除地址、主机名、令牌、证书、私钥、负载和其他敏感网络信息。功能请求应说明操作者问题、受限授权范围，以及现有行为为何不足。

不要在公开 issue 中报告安全漏洞，请遵循[安全策略](SECURITY.zh-CN.md)。

## 行为准则

参与本项目须遵守[行为准则](CODE_OF_CONDUCT.zh-CN.md)。
