import re
import json
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="InjectorX Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_ID = "qwen3.5:4b"
OLLAMA_BASE_URL = "http://localhost:11434"

AGENT_SYSTEM_PROMPT = """你是InjectorX,一个SQL注入自动化专家。你必须严格按照以下格式输出，不要有任何多余内容：

Thought: 简短说明下一步（不超过10个词）
Action: 工具调用或Finish[答案]

可用工具：
- run_sqlmap_get_DB(url)
- run_sqlmap_get_TB(url, database)
- run_sqlmap_get_column(url, database, table)
- run_sqlmap_get_dump(url, database, table, column=None)

# 重要：名称有效性规则
- 真正的数据库名、表名、列名只能包含字母（a-z, A-Z）、数字（0-9）和下划线（_）
- 如果工具返回的名称中包含以下任何字符：`.` `,` `[` `]` `-` `|` `'` 空格或其他标点符号，则视为**脏数据**，不是真正的名称
- 遇到脏数据时，不要使用它们，应当忽略并尝试其他数据库/表/列，或者重新运行工具

示例：
Thought: 获取数据库列表。
Action: run_sqlmap_get_DB(url="http://example.com")

得到结果后，继续下一步。当你获得flag时：
Action: Finish[flag值]

现在开始执行。"""

import requests


class OllamaClient:
    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def generate_stream(self, prompt: str, system_prompt: str):
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": True,
            "options": {
                "temperature": 0,
                "num_predict": 256
            }
        }
        try:
            response = requests.post(url, json=payload, stream=True)
            if response.status_code != 200:
                return f"错误: Ollama 返回错误 (状态码 {response.status_code})"
            full_content = ""
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line.decode('utf-8'))
                        if 'message' in chunk and 'content' in chunk['message']:
                            content = chunk['message']['content']
                            full_content += content
                        if chunk.get('done', False):
                            break
                    except json.JSONDecodeError:
                        continue
            return full_content.strip() if full_content else "错误: 模型未返回任何输出"
        except Exception as e:
            return f"错误: 调用语言模型服务时出错 - {str(e)}"


from tools.run_sqlmap_get_DB import run_sqlmap_get_DB
from tools.run_sqlmap_get_TB import run_sqlmap_get_TB
from tools.run_sqlmap_get_column import run_sqlmap_get_column
from tools.run_sqlmap_get_dump import run_sqlmap_get_dump

available_tools = {
    "run_sqlmap_get_DB": run_sqlmap_get_DB,
    "run_sqlmap_get_TB": run_sqlmap_get_TB,
    "run_sqlmap_get_column": run_sqlmap_get_column,
    "run_sqlmap_get_dump": run_sqlmap_get_dump,
}


class InjectRequest(BaseModel):
    url: str


async def generate_inject_events(url: str):
    llm = OllamaClient(model=MODEL_ID, base_url=OLLAMA_BASE_URL)
    prompt_history = [f"用户请求: {url}"]

    yield f"data: {json.dumps({'type': 'user', 'content': f'目标 URL: {url}'}, ensure_ascii=False)}\n\n"
    yield f"data: {json.dumps({'type': 'separator', 'content': '='*50}, ensure_ascii=False)}\n\n"

    MAX_LOOPS = 15

    for i in range(MAX_LOOPS):
        yield f"data: {json.dumps({'type': 'loop', 'content': f'--- 循环 {i+1} ---'}, ensure_ascii=False)}\n\n"

        full_prompt = "\n".join(prompt_history)
        llm_output = llm.generate_stream(full_prompt, system_prompt=AGENT_SYSTEM_PROMPT)

        yield f"data: {json.dumps({'type': 'llm_raw', 'content': f'[DEBUG] 模型原始输出: {llm_output}'}, ensure_ascii=False)}\n\n"

        if not llm_output or llm_output.startswith("错误:"):
            observation = llm_output if llm_output else "错误: 模型未返回任何输出，请检查Ollama服务或模型。"
            observation_str = f"Observation: {observation}"
            yield f"data: {json.dumps({'type': 'observation', 'content': observation_str}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({'type': 'separator', 'content': '='*50}, ensure_ascii=False)}\n\n"
            prompt_history.append(observation_str)
            continue

        match = re.search(r'(Thought:.*?Action:.*?)(?=\n\s*(?:Thought:|Action:|Observation:)|\Z)', llm_output, re.DOTALL)
        if match:
            truncated = match.group(1).strip()
            if truncated != llm_output.strip():
                llm_output = truncated
                yield f"data: {json.dumps({'type': 'info', 'content': '已截断多余的 Thought-Action 对'}, ensure_ascii=False)}\n\n"

        yield f"data: {json.dumps({'type': 'llm', 'content': llm_output}, ensure_ascii=False)}\n\n"
        prompt_history.append(llm_output)

        action_match = re.search(r"Action: (.*)", llm_output, re.DOTALL)
        if not action_match:
            observation = "错误: 未能解析到 Action 字段。请严格确保格式正确。"
            observation_str = f"Observation: {observation}"
            yield f"data: {json.dumps({'type': 'observation', 'content': observation_str}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({'type': 'separator', 'content': '='*50}, ensure_ascii=False)}\n\n"
            prompt_history.append(observation_str)
            continue

        action_str = action_match.group(1).strip()
        action_str = action_str.strip('`').strip()

        if action_str.startswith("Finish"):
            final_match = re.match(r"Finish\[(.*)\]", action_str)
            if final_match:
                final_answer = final_match.group(1)
            else:
                final_answer = action_str[7:-1] if action_str.endswith("]") else "解析失败"
            yield f"data: {json.dumps({'type': 'final', 'content': f'任务完成，最终答案: {final_answer}'}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'content': ''}, ensure_ascii=False)}\n\n"
            break

        tool_match = re.match(r"(\w+)\((.*)\)", action_str)
        if not tool_match:
            observation = f"错误: Action 格式不正确，得到: {action_str}"
            observation_str = f"Observation: {observation}"
            yield f"data: {json.dumps({'type': 'observation', 'content': observation_str}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({'type': 'separator', 'content': '='*50}, ensure_ascii=False)}\n\n"
            prompt_history.append(observation_str)
            continue

        tool_name = tool_match.group(1)
        args_str = tool_match.group(2)

        kwargs = {}
        for arg_match in re.finditer(r'(\w+)=(["\'])([^\2]+?)\2', args_str):
            key = arg_match.group(1)
            value = arg_match.group(3)
            kwargs[key] = value

        if tool_name in available_tools:
            try:
                observation = available_tools[tool_name](**kwargs)
            except Exception as e:
                observation = f"工具执行异常: {str(e)}"
        else:
            observation = f"错误: 未知工具 '{tool_name}'，可用: {', '.join(available_tools.keys())}"

        observation_str = f"Observation: {observation}"
        yield f"data: {json.dumps({'type': 'observation', 'content': observation_str}, ensure_ascii=False)}\n\n"
        yield f"data: {json.dumps({'type': 'separator', 'content': '='*50}, ensure_ascii=False)}\n\n"
        prompt_history.append(observation_str)
    else:
        yield f"data: {json.dumps({'type': 'final', 'content': '达到最大循环次数，任务未完成。'}, ensure_ascii=False)}\n\n"
        yield f"data: {json.dumps({'type': 'done', 'content': ''}, ensure_ascii=False)}\n\n"


@app.post("/inject")
async def inject(request: InjectRequest):
    return StreamingResponse(
        generate_inject_events(request.url),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@app.get("/")
async def root():
    html_content = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InjectorX - SQL Injection Agent</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: #0a0a0a;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Courier New', monospace;
            overflow: hidden;
        }

        #matrix-canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
        }

        .container {
            position: relative;
            z-index: 1;
            width: 90%;
            max-width: 900px;
        }

        .terminal {
            background: rgba(20, 0, 0, 0.85);
            border: 2px solid #00ff41;
            border-radius: 10px;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.3), 0 0 60px rgba(255, 0, 0, 0.1), inset 0 0 60px rgba(0, 255, 65, 0.05);
            padding: 30px;
        }

        .terminal-header {
            display: flex;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(0, 255, 65, 0.3);
        }

        .terminal-title {
            font-size: 28px;
            color: #00ff41;
            text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41;
            letter-spacing: 4px;
            font-weight: bold;
        }

        .cursor {
            display: inline-block;
            width: 15px;
            height: 28px;
            background: #00ff41;
            margin-left: 10px;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }

        .input-section {
            margin-bottom: 25px;
        }

        .input-label {
            color: #00ff41;
            font-size: 14px;
            margin-bottom: 10px;
            display: block;
            text-shadow: 0 0 5px #00ff41;
        }

        .input-row {
            display: flex;
            gap: 15px;
        }

        #url-input {
            flex: 1;
            background: rgba(0, 255, 65, 0.1);
            border: 1px solid #00ff41;
            border-radius: 5px;
            padding: 15px;
            font-size: 16px;
            color: #00ff41;
            font-family: 'Courier New', monospace;
            outline: none;
            transition: all 0.3s;
        }

        #url-input:focus {
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.5);
            background: rgba(0, 255, 65, 0.15);
        }

        #url-input::placeholder {
            color: rgba(0, 255, 65, 0.4);
        }

        #inject-btn {
            background: linear-gradient(135deg, #003300 0%, #001a00 100%);
            border: 2px solid #00ff41;
            color: #00ff41;
            padding: 15px 30px;
            font-size: 16px;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            border-radius: 5px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 2px;
            transition: all 0.3s;
            text-shadow: 0 0 5px #00ff41;
        }

        #inject-btn:hover:not(:disabled) {
            background: rgba(0, 255, 65, 0.2);
            box-shadow: 0 0 25px rgba(0, 255, 65, 0.6), 0 0 50px rgba(0, 255, 65, 0.3);
            transform: translateY(-2px);
        }

        #inject-btn:active:not(:disabled) {
            transform: translateY(0);
        }

        #inject-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .output-section {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(0, 255, 65, 0.3);
            border-radius: 5px;
            padding: 20px;
            height: 450px;
            overflow-y: auto;
            font-size: 14px;
        }

        .output-section::-webkit-scrollbar {
            width: 8px;
        }

        .output-section::-webkit-scrollbar-track {
            background: rgba(0, 255, 65, 0.1);
        }

        .output-section::-webkit-scrollbar-thumb {
            background: #00ff41;
            border-radius: 4px;
        }

        .output-line {
            color: #00ff41;
            margin-bottom: 8px;
            line-height: 1.6;
            text-shadow: 0 0 3px rgba(0, 255, 65, 0.5);
            animation: fadeIn 0.3s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .output-line.separator {
            color: rgba(0, 255, 65, 0.5);
        }

        .output-line.user {
            color: #00ffff;
            text-shadow: 0 0 5px #00ffff;
        }

        .output-line.llm {
            color: #ffff00;
            text-shadow: 0 0 5px #ffff00;
        }

        .output-line.observation {
            color: #ff00ff;
            text-shadow: 0 0 5px #ff00ff;
        }

        .output-line.final {
            color: #00ff41;
            font-weight: bold;
            font-size: 18px;
            text-shadow: 0 0 10px #00ff41;
            background: rgba(0, 255, 65, 0.1);
            padding: 10px;
            border-radius: 5px;
            margin-top: 15px;
        }

        .output-line.debug {
            color: #888;
            font-style: italic;
        }

        .output-line.error {
            color: #ff3333;
            text-shadow: 0 0 5px #ff0000;
            font-weight: bold;
        }

        .output-line.info {
            color: #00ffff;
        }

        .output-line.loop {
            color: #ffaa00;
            font-weight: bold;
        }

        .typing-indicator {
            color: #00ff41;
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
    </style>
</head>
<body>
    <canvas id="matrix-canvas"></canvas>
    
    <div class="container">
        <div class="terminal">
            <div class="terminal-header">
                <span class="terminal-title">InjectorX</span>
                <span class="cursor"></span>
            </div>
            
            <div class="input-section">
                <label class="input-label">>> 输入目标 URL:</label>
                <div class="input-row">
                    <input type="text" id="url-input" placeholder="http://example.com/vuln.php?id=1" />
                    <button id="inject-btn">开始注入</button>
                </div>
            </div>
            
            <div class="output-section" id="output">
                <div class="output-line info">[+] InjectorX Agent 就绪...</div>
            </div>
        </div>
    </div>

    <script>
        const canvas = document.getElementById('matrix-canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?injectorx';
        const fontSize = 14;
        const columns = Math.floor(canvas.width / fontSize);
        const drops = Array(columns).fill(1);
        
        function drawMatrix() {
            ctx.fillStyle = 'rgba(10, 10, 10, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#00ff41';
            ctx.font = fontSize + 'px monospace';
            
            for (let i = 0; i < drops.length; i++) {
                const char = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(char, i * fontSize, drops[i] * fontSize);
                
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }
        
        setInterval(drawMatrix, 50);
        
        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });

        const urlInput = document.getElementById('url-input');
        const injectBtn = document.getElementById('inject-btn');
        const output = document.getElementById('output');
        
        let isRunning = false;
        
        function addOutput(content, className = '') {
            const line = document.createElement('div');
            line.className = 'output-line' + (className ? ' ' + className : '');
            line.textContent = content;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }
        
        function addTypingIndicator() {
            const indicator = document.createElement('div');
            indicator.className = 'output-line typing-indicator';
            indicator.id = 'typing';
            indicator.textContent = '[*] 正在思考...';
            output.appendChild(indicator);
            output.scrollTop = output.scrollHeight;
            return indicator;
        }
        
        function removeTypingIndicator(indicator) {
            if (indicator && indicator.parentNode) {
                indicator.parentNode.removeChild(indicator);
            }
        }
        
        injectBtn.addEventListener('click', async () => {
            const url = urlInput.value.trim();
            if (!url) {
                addOutput('[-] 错误: 请输入目标 URL', 'debug');
                return;
            }
            
            if (isRunning) {
                addOutput('[*] 任务正在进行中，请等待...', 'info');
                return;
            }
            
            isRunning = true;
            injectBtn.disabled = true;
            output.innerHTML = '';
            
            const typingIndicator = addTypingIndicator();
            
            try {
                const response = await fetch('/inject', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url: url }),
                });
                
                removeTypingIndicator(typingIndicator);
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';
                
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\\n');
                    buffer = lines.pop() || '';
                    
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                const data = JSON.parse(line.slice(6));
                                handleStreamData(data);
                            } catch (e) {
                                console.error('Parse error:', e);
                            }
                        }
                    }
                }
                
                for (const line of buffer.split('\\n')) {
                    if (line.startsWith('data: ')) {
                        try {
                            const data = JSON.parse(line.slice(6));
                            handleStreamData(data);
                        } catch (e) {
                            console.error('Parse error:', e);
                        }
                    }
                }
                
            } catch (error) {
                removeTypingIndicator(typingIndicator);
                addOutput('[-] 请求失败: ' + error.message, 'debug');
            } finally {
                isRunning = false;
                injectBtn.disabled = false;
            }
        });
        
        function handleStreamData(data) {
            switch(data.type) {
                case 'user':
                    addOutput(data.content, 'user');
                    break;
                case 'separator':
                    addOutput(data.content, 'separator');
                    break;
                case 'loop':
                    addOutput(data.content, 'loop');
                    break;
                case 'llm_raw':
                    addOutput(data.content, 'debug');
                    break;
                case 'llm':
                    addOutput(data.content, 'llm');
                    break;
                case 'observation':
                    addOutput(data.content, 'observation');
                    break;
                case 'final':
                    addOutput(data.content, 'final');
                    break;
                case 'info':
                    addOutput(data.content, 'info');
                    break;
                case 'done':
                    addOutput('[+] 任务执行完成', 'info');
                    break;
            }
        }
        
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                injectBtn.click();
            }
        });
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
