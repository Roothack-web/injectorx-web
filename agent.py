import re
from tools.OllamaClient import OllamaClient
from tools.run_sqlmap_get_DB import run_sqlmap_get_DB
from tools.run_sqlmap_get_TB import run_sqlmap_get_TB
from tools.run_sqlmap_get_column import run_sqlmap_get_column
from tools.run_sqlmap_get_dump import run_sqlmap_get_dump
from config import SQLMAP_PATH
# ================== 系统提示词（精简强制格式） ==================
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
- 如果工具返回的名称中包含以下任何字符：`.` `,` `[` `]` `-` `|` `'` 空格或其他标点符号以及连续的相同字母，则视为**脏数据**，不是真正的名称
- 遇到脏数据时，不要使用它们，应当忽略并尝试其他数据库/表/列，或者重新运行工具

示例：
Thought: 获取数据库列表。
Action: run_sqlmap_get_DB(url="http://example.com")

得到结果后，继续下一步。当你获得flag时：
Action: Finish[flag值]

现在开始执行。"""


available_tools = {
    "run_sqlmap_get_DB": run_sqlmap_get_DB,
    "run_sqlmap_get_TB": run_sqlmap_get_TB,
    "run_sqlmap_get_column": run_sqlmap_get_column,
    "run_sqlmap_get_dump": run_sqlmap_get_dump,
}

MODEL_ID = "qwen3.5:4b"   # 请确保已通过 ollama pull qwen3.5:4b 下载
OLLAMA_BASE_URL = "http://localhost:11434"

llm = OllamaClient(
    model=MODEL_ID,
    base_url=OLLAMA_BASE_URL
)

# ================== 主循环 ==================
def main():
    user_prompt = input("请输入漏洞URL: ")
    prompt_history = [f"用户请求: {user_prompt}"]
    print(f"用户输入: {user_prompt}\n" + "="*40)

    MAX_LOOPS = 15

    for i in range(MAX_LOOPS):
        print(f"--- 循环 {i+1} ---\n")
        full_prompt = "\n".join(prompt_history)

        llm_output = llm.generate_stream(full_prompt, system_prompt=AGENT_SYSTEM_PROMPT)
        print(f"[DEBUG] 模型原始输出: '{llm_output}'")   # 调试输出

        if not llm_output:
            observation = "错误: 模型未返回任何输出，请检查Ollama服务或模型。"
            observation_str = f"Observation: {observation}"
            print(f"{observation_str}\n" + "="*40)
            prompt_history.append(observation_str)
            continue

        # 截断多余的 Thought-Action 对
        match = re.search(r'(Thought:.*?Action:.*?)(?=\n\s*(?:Thought:|Action:|Observation:)|\Z)', llm_output, re.DOTALL)
        if match:
            truncated = match.group(1).strip()
            if truncated != llm_output.strip():
                llm_output = truncated
                print("已截断多余的 Thought-Action 对")
        print()
        prompt_history.append(llm_output)

        # 解析 Action
        action_match = re.search(r"Action: (.*)", llm_output, re.DOTALL)
        if not action_match:
            observation = "错误: 未能解析到 Action 字段。请严格确保格式正确。"
            observation_str = f"Observation: {observation}"
            print(f"{observation_str}\n" + "="*40)
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
            print(f"任务完成，最终答案: {final_answer}")
            break

        tool_match = re.match(r"(\w+)\((.*)\)", action_str)
        if not tool_match:
            observation = f"错误: Action 格式不正确，得到: {action_str}"
            observation_str = f"Observation: {observation}"
            print(f"{observation_str}\n" + "="*40)
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
        print(f"{observation_str}\n" + "="*40)
        prompt_history.append(observation_str)

    else:
        print("达到最大循环次数，任务未完成。")

if __name__ == "__main__":
    main()