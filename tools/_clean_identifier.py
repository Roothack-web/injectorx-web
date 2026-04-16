import re


def _clean_identifier(name: str) -> bool:
    """判断是否为合法的标识符（字母数字下划线，且不是常见的垃圾词）"""
    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        return False
    garbage = {'___', '__H__', '_', '--', '...', 'V...', 'https://sqlmap.org',
               'starting', 'ending', 'Column', 'Type', 'Table', 'Database'}
    return name not in garbage
