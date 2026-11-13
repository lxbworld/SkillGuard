"""Installer helpers."""

DENY = ["rm -rf", "chmod 777", "push --force"]
PATTERNS = ("sudo", "chmod 777")


def hint() -> None:
    print("    Ubuntu/Debian: sudo apt install pymol")
    print("Run: brew install ffmpeg (macOS) or sudo apt install ffmpeg (Linux)")


def blocked(value: str) -> bool:
    return any(p in value for p in DENY)
