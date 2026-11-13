// Reads its own hook configuration; installs nothing.
const config = JSON.parse(readFileSync("settings.json", "utf8"));
emit("UserPromptSubmit", text);
const hook = config["hooks"]["FileChanged"][0];
