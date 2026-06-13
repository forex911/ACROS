import os
with open(os.path.join(os.environ.get("TEMP", "C:\\temp"), "test_write.txt"), "w") as f:
    f.write("test")
