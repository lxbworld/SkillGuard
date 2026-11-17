import { exec } from "node:child_process";
// Subprocess invocation: SHELL_EXEC's claim, not dynamic evaluation.
exec(cmd, (err) => {});
exec('git', ['rev-parse'], { cwd: projectRoot });
const localBin = resolve(__dirname, "../../../bin/s2-docs.js");
