// A user-agent and a library version. Both look like an IPv4 address to a naive
// pattern, and neither is a network destination. `research/GOLD.md` records the
// old `DL_UNTRUSTED_DOMAIN` firing on `Chrome/120.0.0.0`.
const userAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const engineVersion = "1.2.3.4";

function banner() {
  return `${userAgent} (engine ${engineVersion})`;
}

module.exports = { banner };
