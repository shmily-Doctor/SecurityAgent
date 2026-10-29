# SecurityAgent

本项目原创代码采用 MIT 许可证，见 `LICENSE.md`。Nmap 需自行安装并遵守其自身许可证，本仓库不分发 Nmap。

`security_lab` 包含用于静态扫描练习的故意不安全示例，请勿用于生产环境。

Python 安全学习与审计助手，提供 Bandit 扫描、实验代码修复、本机站点检查和报告生成。

## 安装与运行

需要 Python 3.14 和可访问的模型 API。Windows PowerShell 示例：

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:DASHSCOPE_API_KEY = "你的密钥"
.\.venv\Scripts\python.exe main.py
```

也可按 `config.py` 配置 `DEEPSEEK_API_KEY` 或 `OPENAI_API_KEY`。请勿提交密钥或 `.env` 文件。源码和工具结果可能发送至所选模型服务；请先检查内容是否含有敏感信息，内置脱敏不能保证覆盖所有凭据。

运行全部测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

项目扫描只覆盖 `security_lab`，不是整个仓库。修复仅允许该目录下的单个 Python 文件，并需要在终端输入 `APPLY` 批准；超出读取上限的文件不能使用整文件修复。测试工具会执行实验代码，请仅在可信的隔离环境中使用。

本机爬虫访问回环地址；公网爬虫支持 HTTP/HTTPS，仅抓取同源页面，且不跟随重定向。请只抓取有权访问的网站，并遵守目标站点的规则；该工具不会自动检查 robots.txt。网络检查固定扫描本机端口。Nmap 需要单独安装或放入 `vendor/nmap`。
