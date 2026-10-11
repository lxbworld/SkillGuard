"""Print the configuration template committed with the skill."""

with open(".env.example") as fh:
    print(fh.read())
