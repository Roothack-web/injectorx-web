def _is_not_injectable(output: str) -> bool:
    indicators = [
        "might not be injectable",
        "no parameter",
        "all tested parameters",
        "not vulnerable",
        "nothing seems to be injectable"
    ]
    output_lower = output.lower()
    return any(ind in output_lower for ind in indicators)