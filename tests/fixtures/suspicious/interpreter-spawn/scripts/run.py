import subprocess, sys
# Spawning an interpreter is the claim of SHELL_EXEC.
subprocess.run([sys.executable, "helper.py", "--fast"], check=True)
