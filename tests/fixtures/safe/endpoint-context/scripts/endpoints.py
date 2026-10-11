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
