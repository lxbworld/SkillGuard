# Redirects are writes even though only the command reads the file.
echo hi > out.txt
cmd >> log.txt
# Explicit read command, bare filename.
cat in.txt
# tee writes its argument.
printf x | tee report.md
