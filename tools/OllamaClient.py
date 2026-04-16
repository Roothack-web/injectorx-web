import json

import requests


class OllamaClient:
    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def generate_stream(self, prompt: str, system_prompt: str) -> str:
        print("正在调用本地 Ollama 模型（流式）...")
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
                error_text = response.text
                print(f"Ollama 返回错误 (状态码 {response.status_code}): {error_text}")
                return f"错误: {error_text}"
            response.raise_for_status()
            full_content = ""
            print("模型输出（流式）: ", end="", flush=True)
            for line in response.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line.decode('utf-8'))
                        if 'message' in chunk and 'content' in chunk['message']:
                            content = chunk['message']['content']
                            print(content, end="", flush=True)
                            full_content += content
                        if chunk.get('done', False):
                            break
                    except json.JSONDecodeError:
                        continue
            print("\n本地模型流式响应结束。")
            return full_content.strip()
        except Exception as e:
            print(f"\n调用 Ollama API 时发生错误: {e}")
            return "错误: 调用本地语言模型服务时出错。"