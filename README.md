# InjectorX Web Application

InjectorX 是一个基于 FastAPI 和 HTML/JS 的 SQL 注入自动化测试工具，提供了炫酷的黑客风格 Web 界面。

## 🎨 功能特性

- **黑客风格界面**：Matrix 代码雨动画背景 + 暗黑主题 + 绿色荧光字体
- **实时流式输出**：Agent 的思考过程和工具调用结果实时显示
- **SQL 注入测试**：集成 SQLMap 工具进行数据库探测和数据提取
- **智能 Agent**：使用本地大语言模型（Ollama）进行决策
- **Web 交互**：通过浏览器即可操作，无需命令行

## 🚀 快速开始

### 环境要求

- Python 3.8+
- Ollama 服务（运行在 `localhost:11434`）
- SQLMap 工具

### 安装步骤

1. **克隆仓库**
```bash
git clone https://github.com/Roothack-web/injectorx-web.git
cd injectorx-web
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **配置 SQLMap 路径**
编辑 `config.py` 文件，设置正确的 SQLMap 路径：
```python
SQLMAP_PATH = "C:\path\to\sqlmap\sqlmap.py"
```

4. **启动 Ollama 服务**
确保 Ollama 服务正在运行，并下载了 `qwen3.5:4b` 模型：
```bash
ollama pull qwen3.5:4b
ollama serve
```

5. **启动应用**
```bash
uvicorn backend:app --reload
```

6. **访问应用**
打开浏览器访问：`http://127.0.0.1:8000`

## 📖 使用方法

1. 在输入框中输入目标 URL（如 `http://example.com/vuln.php?id=1`）
2. 点击 "开始注入" 按钮
3. 观察终端区域的实时输出，包括：
   - Agent 的思考过程（Thought）
   - 工具调用（Action）
   - 执行结果（Observation）
4. 等待 Agent 完成任务，最终会显示提取到的 flag 或数据

## 🔧 技术栈

- **后端**：FastAPI (Python)
- **前端**：HTML5, CSS3, JavaScript
- **AI 模型**：Ollama (qwen3.5:4b)
- **工具集成**：SQLMap
- **通信**：Server-Sent Events (SSE)

## 📁 项目结构

```
injectorx-web/
├── backend.py          # FastAPI 后端（集成 Agent 逻辑 + 前端 HTML）
├── agent.py            # 原始 Agent 代码
├── config.py           # 配置文件（SQLMap 路径）
├── requirements.txt    # 依赖包
├── tools/              # 工具模块
│   ├── OllamaClient.py         # Ollama 客户端
│   ├── run_sqlmap_get_DB.py    # 获取数据库列表
│   ├── run_sqlmap_get_TB.py    # 获取表列表
│   ├── run_sqlmap_get_column.py # 获取列列表
│   └── run_sqlmap_get_dump.py  # 提取数据
└── .gitignore
```

## ⚠️ 注意事项

- **仅供学习使用**：本工具仅用于合法的渗透测试和安全研究
- **环境配置**：确保 Ollama 服务和 SQLMap 工具正确配置
- **网络安全**：使用时需遵守相关法律法规
- **性能考虑**：SQL 注入测试可能需要较长时间，请耐心等待

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！

## 📄 许可证

MIT License

---

**Happy Hacking!** 🎯