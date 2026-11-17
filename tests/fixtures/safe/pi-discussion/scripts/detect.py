# A scanner's own pattern table: every rule id matches the words inside.
PATTERNS = [
    ("child_process_exec", r"""\b(?:child_process\.exec|execSync|exec)\s*\(""", "CRITICAL"),
    ("pipe_to_shell", r"""(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|zsh)""", "HIGH"),
    ("ignore_override", r"""ignore (all )?(previous|prior) instructions""", "HIGH"),
]
