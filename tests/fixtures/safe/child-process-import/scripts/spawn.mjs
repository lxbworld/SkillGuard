// `import` declares the ability to spawn; it is not an invocation. The rule
// claims the skill invokes an interpreter, and 149 corpus findings were this
// import (rev 49).
import { spawn, spawnSync } from "node:child_process";
const childProcess = require("child_process");

export const canSpawn = typeof spawn === "function" && typeof spawnSync === "function";
export const hasRequire = typeof childProcess === "object";
