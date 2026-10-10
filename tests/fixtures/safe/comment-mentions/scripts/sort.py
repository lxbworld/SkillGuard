# This helper's comments mention ~/.ssh/id_rsa and https://evil.example.com only
# to document what an operator might point it at. The comments are not behaviour:
# the function reads the path it is given and nothing else.
import sys


def sort_names(path):
    with open(path) as fh:
        return sorted(line.strip() for line in fh)


if __name__ == "__main__":
    for name in sort_names(sys.argv[1]):
        print(name)
