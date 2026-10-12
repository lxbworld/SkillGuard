"""Endpoint constants the operator may contact.

`.xyz`, `.top` and `.rest` below are data and documentation formats in the
path, not country-code hosts. The addresses are loopback or RFC 1918, which the
rule says are not untrusted endpoints.
"""

STRUCTURES = "https://files.example.org/demo/water.xyz"
GUIDE = "https://docs.example.org/guide/intro.rest"
SAMPLES = "https://cdn.example.org/data/sample.top"

LOCAL_HEALTH = "http://127.0.0.1:8080/health"
GATEWAY = "http://192.168.1.1/status"
METRICS = "http://10.0.0.5/metrics"

# A long label is a real company name, not a generated domain, and `1.2.3.4`
# is the canonical documentation placeholder. Neither is an endpoint the rule
# claims is contacted (rev 46).
MARKET_DATA = "https://financialmodelingprep.com/api/v3/"
PANEL = "https://1.2.3.4:8888"
