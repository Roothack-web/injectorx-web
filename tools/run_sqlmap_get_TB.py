import re
import subprocess
from config import SQLMAP_PATH
from tools._clean_identifier import _clean_identifier
from tools.is_not_injectable import _is_not_injectable


def run_sqlmap_get_TB(url: str, database: str) -> str:
    if 'http' not in url.lower():
        return "URL格式错误"

    cmd = [
        "python", SQLMAP_PATH,
        "-u", url,
        "-D", database,
        "--tables",
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

        tables = []
        # 策略1: 匹配 resumed: 'table_name'
        tables = re.findall(r"resumed:\s+'([^']+)'", output, re.IGNORECASE)
        if not tables:
            # 策略2: 在 "Database:" 之后解析表格
            in_table_section = False
            for line in output.split('\n'):
                if re.search(r'Database: \w+', line, re.IGNORECASE):
                    in_table_section = True
                    continue
                if in_table_section and '|' in line and not line.strip().startswith('+'):
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    for p in parts:
                        if _clean_identifier(p):
                            tables.append(p)
        tables = list(dict.fromkeys(tables))
        if tables:
            return f"数据库 {database} 中的表: {', '.join(tables)}。请选择要dump的表。"
        else:
            return f"未找到表。输出片段:\n{output[:800]}"
    except Exception as e:
        return f"错误: {str(e)}"