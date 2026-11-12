"""This docstring never closes.

Everything after it is technically still inside the string, so a lexer reports
the whole file as documentation. The requirement is that the scanner still
returns and still reports the file: suppressing the rest is acceptable,
crashing or silently scanning nothing is not.
"""

print("the file must not crash the scanner")
